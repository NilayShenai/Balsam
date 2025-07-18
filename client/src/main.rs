use ed25519_dalek::{SigningKey, VerifyingKey};
use protocol::{
    decrypt_message, encrypt_message, AuthReqPayload, AuthResponsePayload, FetchPKeyPayload, Frame,
    HandshakePayload, OpCode, RegisterPayload, SendMsgPayload,
};
use std::{fs, io::{self, Write}, path::Path, str::FromStr};
use tokio::{io::BufReader, net::TcpStream};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const SERVER_ADDRESS: &str = "127.0.0.1:9600";
const KEY_FILE: &str = "balsam_key.bin";
const DOMAIN: &str = "000196.xyz";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = load_or_generate_keypair()?;
    let mut stream = TcpStream::connect(SERVER_ADDRESS).await?;
    println!("🔌 Connecting to Balsam network...");

    let syn_frame = Frame::new(OpCode::Syn, &HandshakePayload { version: protocol::VERSION });
    syn_frame.write_to_stream(&mut stream).await?;
    let ack_frame = Frame::read_from_stream(&mut stream).await?;
    if ack_frame.opcode != OpCode::Ack {
        println!("Handshake failed!");
        return Ok(());
    }
    println!("Connection established. Type 'help' for commands.");

    let mut reader = BufReader::new(stream);
    loop {
        print!("> ");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        
        if parts.is_empty() { continue; }

        match parts[0] {
            "quit" => break,
            "help" => print_help(),
            "register" => handle_register(&mut reader, &keypair, &parts).await?,
            "login" => handle_login(&mut reader, &keypair, &parts).await?,
            "send" => handle_send(&mut reader, &keypair, &parts).await?,
            "inbox" => handle_inbox(&mut reader, &keypair).await?,
            _ => println!("Unknown command. Type 'help'."),
        }
    }
    Ok(())
}

async fn handle_register(stream: &mut BufReader<TcpStream>, keypair: &SigningKey, parts: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let username = parts.get(1).ok_or("Usage: register <username>")?;
    let payload = RegisterPayload { username: username.to_string(), public_key: keypair.verifying_key().to_bytes() };
    let frame = Frame::new(OpCode::Register, &payload);
    frame.write_to_stream(stream.get_mut()).await?;
    print_server_response(stream).await
}

async fn handle_login(stream: &mut BufReader<TcpStream>, keypair: &SigningKey, parts: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let username = parts.get(1).ok_or("Usage: login <username>")?;
    let auth_req_frame = Frame::new(OpCode::AuthReq, &AuthReqPayload { username: username.to_string() });
    auth_req_frame.write_to_stream(stream.get_mut()).await?;
    
    let challenge_frame = Frame::read_from_stream(stream).await?;
    if challenge_frame.opcode == OpCode::Error { return print_server_response_from_frame(challenge_frame); }
    if challenge_frame.opcode != OpCode::AuthChallenge { return Err("Expected Auth Challenge".into()); }
    let challenge: protocol::AuthChallengePayload = challenge_frame.to_payload()?;
    
    let signature = protocol::sign_message(keypair, &challenge.nonce);
    let response_frame = Frame::new(OpCode::AuthResponse, &AuthResponsePayload { signature: signature.to_bytes() });
    response_frame.write_to_stream(stream.get_mut()).await?;
    print_server_response(stream).await
}

async fn handle_send(stream: &mut BufReader<TcpStream>, keypair: &SigningKey, parts: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let recipient_full = parts.get(1).ok_or("Usage: send <user!domain> <message>")?;
    let message = parts[2..].join(" ");
    
    let fetch_frame = Frame::new(OpCode::FetchPKey, &FetchPKeyPayload { username: recipient_full.to_string() });
    fetch_frame.write_to_stream(stream.get_mut()).await?;
    let pkey_frame = Frame::read_from_stream(stream).await?;
    if pkey_frame.opcode != OpCode::PKeyResponse { return Err("Failed to fetch public key".into()); }
    let pkey_payload: protocol::PKeyResponsePayload = pkey_frame.to_payload()?;
    let recipient_pkey_bytes = pkey_payload.public_key.ok_or("Recipient user not found")?;
    let recipient_verify_key = VerifyingKey::from_bytes(&recipient_pkey_bytes)?;
    
    let my_secret = StaticSecret::from(keypair.to_bytes());
    let their_public = X25519PublicKey::from(recipient_verify_key.to_bytes());
    let encrypted_blob = encrypt_message(&my_secret, &their_public, message.as_bytes());
    
    let send_frame = Frame::new(OpCode::SendMsg, &SendMsgPayload { 
        recipient: recipient_full.to_string(), 
        sender_pkey: keypair.verifying_key().to_bytes(),
        encrypted_blob,
    });
    send_frame.write_to_stream(stream.get_mut()).await?;
    print_server_response(stream).await
}

async fn handle_inbox(stream: &mut BufReader<TcpStream>, keypair: &SigningKey) -> Result<(), Box<dyn std::error::Error>> {
    let frame = Frame::new_empty(OpCode::FetchInbox);
    frame.write_to_stream(stream.get_mut()).await?;
    let response_frame = Frame::read_from_stream(stream).await?;
    if response_frame.opcode != OpCode::InboxResponse { return Err("Failed to fetch inbox".into()); }
    
    let payload: protocol::InboxResponsePayload = response_frame.to_payload()?;
    println!("📬 Your Inbox ({} messages):", payload.messages.len());
    
    let my_secret = StaticSecret::from(keypair.to_bytes());
    
    for (i, msg) in payload.messages.iter().enumerate() {
        let sender_verify_key = VerifyingKey::from_bytes(&msg.sender_pkey)?;
        let their_public = X25519PublicKey::from(sender_verify_key.to_bytes());
        
        if let Some(decrypted) = decrypt_message(&my_secret, &their_public, &msg.encrypted_blob) {
            println!("  {}: {}", i + 1, String::from_utf8_lossy(&decrypted));
        } else {
            println!("  {}: [Could not decrypt message]", i + 1);
        }
    }
    Ok(())
}

fn load_or_generate_keypair() -> Result<SigningKey, Box<dyn std::error::Error>> {
    if Path::new(KEY_FILE).exists() {
        let key_bytes = fs::read(KEY_FILE)?;
        let keypair = SigningKey::from_bytes(&key_bytes.try_into().unwrap());
        println!("Private key loaded from {}", KEY_FILE);
        Ok(keypair)
    } else {
        println!("No private key found, generating a new one...");
        let keypair = protocol::generate_keypair();
        fs::write(KEY_FILE, keypair.to_bytes())?;
        println!("New private key saved to {}. Don't lose this file!", KEY_FILE);
        Ok(keypair)
    }
}

async fn print_server_response(stream: &mut BufReader<TcpStream>) -> Result<(), Box<dyn std::error::Error>> {
    let frame = Frame::read_from_stream(stream).await?;
    print_server_response_from_frame(frame)
}

fn print_server_response_from_frame(frame: Frame) -> Result<(), Box<dyn std::error::Error>> {
    match frame.opcode {
        OpCode::Ok => {
            let payload: protocol::OkPayload = frame.to_payload()?;
            println!("Okay {}", payload.message);
        }
        OpCode::Error => {
            let payload: protocol::ErrorPayload = frame.to_payload()?;
            println!(" X {}", payload.message);
        }
        _ => println!("Received unexpected response: {:?}", frame.opcode),
    }
    Ok(())
}

fn print_help() {
    println!("\n--- Balsam Client Help ---");
    println!("register <user>                  - Creates an account for <user>!{}. Uses key from {}", DOMAIN, KEY_FILE);
    println!("login <user>                     - Authenticates as <user>!{} for this session.", DOMAIN);
    println!("send <user!domain> <message>     - Sends an end-to-end encrypted message.");
    println!("inbox                            - Fetches and decrypts your messages.");
    println!("quit                             - Exits the client.");
}