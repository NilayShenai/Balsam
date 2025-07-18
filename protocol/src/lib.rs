use bincode::{deserialize, serialize};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use crc32fast::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

pub const MAGIC_BYTES: [u8; 4] = [0xAE, 0x74, 0x68, 0x72]; 
pub const VERSION: u8 = 0x01;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Syn = 0x01,
    Ack = 0x02,
    Register = 0x10,
    AuthReq = 0x11,
    AuthChallenge = 0x12,
    AuthResponse = 0x13,
    FetchPKey = 0x20,
    PKeyResponse = 0x21,
    SendMsg = 0x30,
    FetchInbox = 0x40,
    InboxResponse = 0x41,
    Ok = 0xFE,
    Error = 0xFF,
}

impl TryFrom<u8> for OpCode {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(OpCode::Syn),
            0x02 => Ok(OpCode::Ack),
            0x10 => Ok(OpCode::Register),
            0x11 => Ok(OpCode::AuthReq),
            0x12 => Ok(OpCode::AuthChallenge),
            0x13 => Ok(OpCode::AuthResponse),
            0x20 => Ok(OpCode::FetchPKey),
            0x21 => Ok(OpCode::PKeyResponse),
            0x30 => Ok(OpCode::SendMsg),
            0x40 => Ok(OpCode::FetchInbox),
            0x41 => Ok(OpCode::InboxResponse),
            0xFE => Ok(OpCode::Ok),
            0xFF => Ok(OpCode::Error),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
pub struct Frame {
    pub opcode: OpCode,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(opcode: OpCode, payload_struct: &impl Serialize) -> Self {
        let payload = serialize(payload_struct).unwrap();
        Self { opcode, payload }
    }

    pub fn new_empty(opcode: OpCode) -> Self {
        Self {
            opcode,
            payload: vec![],
        }
    }

    pub async fn write_to_stream<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
    ) -> std::io::Result<()> {
        stream.write_all(&MAGIC_BYTES).await?;
        stream.write_u8(VERSION).await?;
        stream.write_u8(self.opcode as u8).await?;
        stream.write_u32(self.payload.len() as u32).await?;
        stream.write_all(&self.payload).await?;
        let mut hasher = Hasher::new();
        hasher.update(&self.payload);
        stream.write_u32(hasher.finalize()).await?;
        Ok(())
    }

    pub async fn read_from_stream<R: AsyncReadExt + Unpin>(
        stream: &mut R,
    ) -> std::io::Result<Self> {
        let mut magic = [0u8; 4];
        stream.read_exact(&mut magic).await?;
        if magic != MAGIC_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid magic bytes",
            ));
        }
        let _version = stream.read_u8().await?;
        let opcode = OpCode::try_from(stream.read_u8().await?)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid opcode"))?;
        let payload_len = stream.read_u32().await? as usize;
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload).await?;
        let expected_checksum = stream.read_u32().await?;
        let mut hasher = Hasher::new();
        hasher.update(&payload);
        if expected_checksum != hasher.finalize() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Checksum mismatch",
            ));
        }
        Ok(Self { opcode, payload })
    }

    pub fn to_payload<T: for<'a> Deserialize<'a>>(&self) -> Result<T, bincode::Error> {
        deserialize(&self.payload)
    }
}

#[derive(Serialize, Deserialize, Debug)] pub struct HandshakePayload { pub version: u8 }
#[derive(Serialize, Deserialize, Debug)] pub struct OkPayload { pub message: String }
#[derive(Serialize, Deserialize, Debug)] pub struct ErrorPayload { pub message: String }
#[derive(Serialize, Deserialize, Debug)] pub struct RegisterPayload { pub username: String, pub public_key: [u8; 32] }
#[derive(Serialize, Deserialize, Debug)] pub struct AuthReqPayload { pub username: String }
#[derive(Serialize, Deserialize, Debug)] pub struct AuthChallengePayload { pub nonce: [u8; 32] }
#[derive(Serialize, Deserialize, Debug)] pub struct AuthResponsePayload { pub signature: [u8; 64] }
#[derive(Serialize, Deserialize, Debug)] pub struct FetchPKeyPayload { pub username: String }
#[derive(Serialize, Deserialize, Debug)] pub struct PKeyResponsePayload { pub public_key: Option<[u8; 32]> }
#[derive(Serialize, Deserialize, Debug)] pub struct SendMsgPayload { pub recipient: String, pub sender_pkey: [u8; 32], pub encrypted_blob: Vec<u8> }
#[derive(Serialize, Deserialize, Debug)] pub struct InboxMessage { pub sender_pkey: [u8; 32], pub encrypted_blob: Vec<u8> }
#[derive(Serialize, Deserialize, Debug)] pub struct InboxResponsePayload { pub messages: Vec<InboxMessage> }


pub fn generate_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn sign_message(key: &SigningKey, message: &[u8]) -> Signature {
    key.sign(message)
}

pub fn verify_signature(key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    key.verify(message, signature).is_ok()
}

pub fn encrypt_message(
    my_secret: &StaticSecret,
    their_public: &X25519PublicKey,
    plaintext: &[u8],
) -> Vec<u8> {
    let shared_secret = my_secret.diffie_hellman(their_public);
    let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
    let nonce = Nonce::from_slice(b"balsam_n0");
    cipher.encrypt(nonce, plaintext).expect("encryption failure!")
}

pub fn decrypt_message(
    my_secret: &StaticSecret,
    their_public: &X25519PublicKey,
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let shared_secret = my_secret.diffie_hellman(their_public);
    let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
    let nonce = Nonce::from_slice(b"balsam_n0");
    cipher.decrypt(nonce, ciphertext).ok()
}