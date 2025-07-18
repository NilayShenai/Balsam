# **Balsam**

Balsam is a messaging protocol built for privacy and security from the ground up. If you're looking for a communication system that puts you in control, you've come to the right place. This project is both a specification and a working example, containing everything you need to run your own secure server and chat client.

## **Key Features**

* **Password-less Identity:** Instead of using passwords that can be stolen, your identity is tied to a unique cryptographic key on your computer. You prove who you are by "signing" a random challenge from the server—something only your key can do.
* **End-to-End Encryption:** Messages are scrambled the moment you hit 'send' and can only be unscrambled by the person you sent them to. The server can't read your messages; its only job is to pass along the encrypted data.
* **A Custom Binary Protocol:** Balsam doesn't use standard web protocols like HTTP. It communicates over a lean, custom-built binary protocol, which makes it fast and less exposed to common web vulnerabilities.

## **Project Structure**

```
.
├── protocol/      # Core definitions: shared data structures, protocol specs, crypto functions
├── server/        # The server-side app that handles connections, accounts, message routing
└── client/        # Command-line client for sending and receiving encrypted messages
```

## **Getting Started**

### **Prerequisites**

You'll need a couple of things installed on your system before you begin:

* **The Rust Toolchain:** This includes rustc and cargo. If you don't have it, you can get it from [rust-lang.org](https://www.rust-lang.org/).
* **PostgreSQL:** The database our server uses to keep track of user accounts and their public keys.

### **1. Set Up the Database**

The server needs a place to store data. Let's get PostgreSQL ready.

* First, log in to psql and create a new user and database:

  ```sql
  CREATE USER balsam_user WITH PASSWORD 'your_secure_password';
  CREATE DATABASE balsam_db OWNER balsam_user;
  ```

* Next, create the tables by running the schema:

  ```bash
  psql -U balsam_user -d balsam_db -f server/schema.sql
  ```

### **2. Configure the Server**

* In the `server/` directory, create a file named `.env`.
* Add the following configuration:

  ```env
  DATABASE_URL=postgres://balsam_user:your_secure_password@localhost/balsam_db
  SERVER_DOMAIN=000196.xyz
  SERVER_ADDRESS=127.0.0.1:9600
  ```

### **3. Build and Run**

* **Build the project:**

  ```bash
  cargo build --release
  ```

* **Run the Balsam Server:**

  ```bash
  cargo run --release --bin server
  ```

  Output should include: `Balsam Server listening on 127.0.0.1:9600`

* **Run the Balsam Client (new terminal):**

  ```bash
  cargo run --release --bin client
  ```

  The first time, it will generate your unique key (`balsam_key.bin`).

## **How to Use Balsam**

The client supports the following commands:

| Command                        | Description                                                |
| ------------------------------ | ---------------------------------------------------------- |
| `register <user>`              | Creates your account on the server using your private key. |
| `login <user>`                 | Authenticates your session using your key.                 |
| `send <user!domain> <message>` | Sends an encrypted message to the recipient.               |
| `inbox`                        | Fetches and decrypts all incoming messages.                |
| `help`                         | Lists all available commands.                              |
| `quit`                         | Exits the client.                                          |

### **Example: Two-User Session**

1. **Start the server.**
2. **Terminal A (User 1):**

   ```bash
   cargo run --release --bin client
   > register alice
   > login alice
   ```
3. **Terminal B (User 2):**

   * Delete `balsam_key.bin` created for Alice

   ```bash
   cargo run --release --bin client
   > register bob
   > login bob
   > send alice!000196.xyz Hello from Bob.
   ```
4. **Back in Terminal A:**

   ```bash
   > inbox
   ```

   You should see Bob's message.

## **Protocol Specification (Advanced)**

### **Packet Framing**

All data is transmitted in structured frames:

| Field          | Size (bytes) | Description                         |
| -------------- | ------------ | ----------------------------------- |
| Magic Bytes    | 4            | `0xAE 0x74 0x68 0x72` ("\u00c6thr") |
| Version        | 1            | Current version: `0x01`             |
| OpCode         | 1            | Type of operation                   |
| Payload Length | 4            | `u32` Big Endian                    |
| Payload        | Variable     | Bincode-encoded data                |
| Checksum       | 4            | CRC32 checksum                      |

### **Opcodes**

| OpCode | Name            | Direction       | Description                       |
| ------ | --------------- | --------------- | --------------------------------- |
| `0x01` | SYN             | Client → Server | Initiate handshake                |
| `0x02` | ACK             | Server → Client | Acknowledge handshake             |
| `0x10` | REGISTER        | Client → Server | Register a new user               |
| `0x11` | AUTH\_REQ       | Client → Server | Begin authentication              |
| `0x12` | AUTH\_CHALLENGE | Server → Client | Challenge (nonce) for signing     |
| `0x13` | AUTH\_RESPONSE  | Client → Server | Return signed challenge           |
| `0x20` | FETCH\_PKEY     | Client → Server | Request another user's public key |
| `0x21` | PKEY\_RESPONSE  | Server → Client | Respond with requested key        |
| `0x30` | SEND\_MSG       | Client → Server | Send encrypted message            |
| `0x40` | FETCH\_INBOX    | Client → Server | Request all messages              |
| `0x41` | INBOX\_RESPONSE | Server → Client | Return message list               |
| `0xFE` | OK              | Server → Client | Generic success                   |
| `0xFF` | ERROR           | Server → Client | Generic failure                   |
