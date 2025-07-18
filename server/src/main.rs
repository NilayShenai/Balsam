use ed25519_dalek::{Signature, VerifyingKey};
use protocol::{
    AuthChallengePayload, AuthReqPayload, AuthResponsePayload, ErrorPayload, FetchPKeyPayload,
    Frame, HandshakePayload, InboxMessage, InboxResponsePayload, OkPayload, OpCode,
    PKeyResponsePayload, RegisterPayload, SendMsgPayload,
};
use rand::RngCore;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::{env, net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

enum ConnectionState {
    Handshaking,
    Authenticating { nonce: [u8; 32], username: String },
    Authenticated { username: String },
    Guest, 
}

struct AppState {
    db_pool: PgPool,
    domain: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::from_path("server/.env").ok();

    let db_url = env::var("DATABASE_URL")?;
    let domain = env::var("SERVER_DOMAIN")?;
    let addr = env::var("SERVER_ADDRESS")?;

    let db_pool = PgPoolOptions::new().connect(&db_url).await?;
    let state = Arc::new(AppState { db_pool, domain });

    let listener = TcpListener::bind(&addr).await?;
    println!("Balsam Server listening on {}", addr);

    loop {
        let (stream, socket_addr) = listener.accept().await?;
        let state_clone = Arc::clone(&state);
        println!("Accepted connection from: {}", socket_addr);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, socket_addr, state_clone).await {
                eprintln!("[{}] Connection error: {}", socket_addr, e);
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn_state = ConnectionState::Handshaking;

    loop {
        let frame = match Frame::read_from_stream(&mut stream).await {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[{}] Read frame error: {}. Closing connection.", addr, e);
                break;
            }
        };

        let (new_state, should_break) =
            process_frame(frame, conn_state, &mut stream, &state, addr).await?;

        conn_state = new_state;
        if should_break {
            break;
        }
    }
    println!("[{}] Connection closed.", addr);
    Ok(())
}

async fn process_frame(
    frame: Frame,
    state: ConnectionState,
    stream: &mut TcpStream,
    app_state: &AppState,
    addr: SocketAddr,
) -> Result<(ConnectionState, bool), Box<dyn std::error::Error>> {
    match (state, frame.opcode) {
        (ConnectionState::Handshaking, OpCode::Syn) => {
            let payload: HandshakePayload = frame.to_payload()?;
            if payload.version != protocol::VERSION {
                let err_frame = Frame::new(
                    OpCode::Error,
                    &ErrorPayload {
                        message: "Version mismatch".to_string(),
                    },
                );
                err_frame.write_to_stream(stream).await?;
                return Ok((ConnectionState::Handshaking, true));
            }
            let ack_frame = Frame::new(OpCode::Ack, &HandshakePayload { version: protocol::VERSION });
            ack_frame.write_to_stream(stream).await?;
            println!("[{}] Handshake successful.", addr);
            Ok((ConnectionState::Guest, false))
        }

        (ConnectionState::Guest, OpCode::Register) => {
            let payload: RegisterPayload = frame.to_payload()?;
            let full_address = format!("{}!{}", payload.username, app_state.domain);

            match sqlx::query("INSERT INTO users (id, username, public_key) VALUES ($1, $2, $3)")
                .bind(Uuid::new_v4())
                .bind(&full_address)
                .bind(payload.public_key.as_slice())
                .execute(&app_state.db_pool)
                .await {
                Ok(_) => {
                    let ok_frame = Frame::new(OpCode::Ok, &OkPayload { message: format!("User {} registered", full_address) });
                    ok_frame.write_to_stream(stream).await?;
                }
                Err(e) => {
                    let err_frame = Frame::new(OpCode::Error, &ErrorPayload { message: e.to_string() });
                    err_frame.write_to_stream(stream).await?;
                }
            }
            Ok((ConnectionState::Guest, false))
        }

        (ConnectionState::Guest, OpCode::AuthReq) => {
            let payload: AuthReqPayload = frame.to_payload()?;
            let full_address = format!("{}!{}", payload.username, app_state.domain);

            if sqlx::query("SELECT id FROM users WHERE username = $1").bind(&full_address).fetch_optional(&app_state.db_pool).await?.is_none() {
                let err_frame = Frame::new(OpCode::Error, &ErrorPayload { message: "User not found".to_string() });
                err_frame.write_to_stream(stream).await?;
                return Ok((ConnectionState::Guest, false));
            }

            let mut nonce = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut nonce);
            let challenge_frame = Frame::new(OpCode::AuthChallenge, &AuthChallengePayload { nonce });
            challenge_frame.write_to_stream(stream).await?;
            println!("[{}] Sent auth challenge for {}", addr, full_address);
            Ok((ConnectionState::Authenticating { nonce, username: full_address }, false))
        }

        (ConnectionState::Authenticating { nonce, username }, OpCode::AuthResponse) => {
            let payload: AuthResponsePayload = frame.to_payload()?;
            let user_record = sqlx::query!("SELECT public_key FROM users WHERE username = $1", username).fetch_one(&app_state.db_pool).await?;
            let public_key = VerifyingKey::from_bytes(&user_record.public_key.try_into().unwrap())?;
            let signature = Signature::from_bytes(&payload.signature)?;
            
            if protocol::verify_signature(&public_key, &nonce, &signature) {
                let ok_frame = Frame::new(OpCode::Ok, &OkPayload { message: format!("Welcome, {}", username) });
                ok_frame.write_to_stream(stream).await?;
                println!("[{}] User {} authenticated successfully.", addr, username);
                Ok((ConnectionState::Authenticated { username }, false))
            } else {
                let err_frame = Frame::new(OpCode::Error, &ErrorPayload { message: "Invalid signature".to_string() });
                err_frame.write_to_stream(stream).await?;
                Ok((ConnectionState::Guest, false))
            }
        }

        (ConnectionState::Authenticated { ref username }, OpCode::SendMsg) => {
            let payload: SendMsgPayload = frame.to_payload()?;
            sqlx::query("INSERT INTO messages (id, recipient, sender_pkey, encrypted_blob) VALUES ($1, $2, $3, $4)")
                .bind(Uuid::new_v4())
                .bind(payload.recipient)
                .bind(payload.sender_pkey.as_slice())
                .bind(payload.encrypted_blob)
                .execute(&app_state.db_pool).await?;
            let ok_frame = Frame::new(OpCode::Ok, &OkPayload { message: "Message stored.".to_string() });
            ok_frame.write_to_stream(stream).await?;
            Ok((ConnectionState::Authenticated { username: username.clone() }, false))
        }
        
        (ConnectionState::Authenticated { ref username }, OpCode::FetchInbox) => {
            let records = sqlx::query!("SELECT sender_pkey, encrypted_blob FROM messages WHERE recipient = $1", username).fetch_all(&app_state.db_pool).await?;
            let messages: Vec<InboxMessage> = records.into_iter().map(|r| InboxMessage {
                sender_pkey: r.sender_pkey.try_into().unwrap(),
                encrypted_blob: r.encrypted_blob,
            }).collect();
            let response_frame = Frame::new(OpCode::InboxResponse, &InboxResponsePayload { messages });
            response_frame.write_to_stream(stream).await?;
            Ok((ConnectionState::Authenticated { username: username.clone() }, false))
        }
        
        (any_state, OpCode::FetchPKey) => {
            let payload: FetchPKeyPayload = frame.to_payload()?;
            let record = sqlx::query!("SELECT public_key FROM users WHERE username = $1", payload.username).fetch_optional(&app_state.db_pool).await?;
            let pkey = record.map(|r| r.public_key.try_into().unwrap());
            let response_frame = Frame::new(OpCode::PKeyResponse, &PKeyResponsePayload { public_key: pkey });
            response_frame.write_to_stream(stream).await?;
            Ok((any_state, false)) // Stay in the same state
        }

        (state, opcode) => {
            let err_frame = Frame::new(OpCode::Error, &ErrorPayload { message: format!("Invalid opcode {:?} for current state.", opcode) });
            err_frame.write_to_stream(stream).await?;
            println!("[{}] Invalid opcode {:?} received. Closing connection.", addr, opcode);
            Ok((state, true))
        }
    }
}