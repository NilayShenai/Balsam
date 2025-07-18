# **Welcome to Balsam**

Balsam is a messaging protocol built for privacy and security from the ground up. If you're looking for a communication system that puts you in control, you've come to the right place. This project is both a specification and a working example, containing everything you need to run your own secure server and chat client.

## **Key Features**

* **Password-less Identity:** Instead of using passwords that can be stolen, your identity is tied to a unique cryptographic key on your computer. You prove who you are by "signing" a random challenge from the server—something only your key can do.  
* **End-to-End Encryption:** Messages are scrambled the moment you hit 'send' and can only be unscrambled by the person you sent them to. The server can't read your messages; its only job is to pass along the encrypted data.  
* **A Custom Binary Protocol:** Balsam doesn't use standard web protocols like HTTP. It communicates over a lean, custom-built binary protocol, which makes it fast and less exposed to common web vulnerabilities.

## **Project Structure**

.  
├── protocol/  
│   \# The heart of the project. Defines the shared language,  
│   \# data structures, and crypto functions for the client and server.  
│  
├── server/  
│   \# The server-side application that listens for connections,  
│   \# manages accounts, and routes encrypted messages.  
│  
└── client/  
    \# The command-line client you'll use to connect to the  
    \# Balsam network and chat with others.

## **Getting Started**

### **Prerequisites**

You'll need a couple of things installed on your system before you begin:

* **The Rust Toolchain:** This includes rustc and cargo. If you don't have it, you can get it from [rust-lang.org](https://www.rust-lang.org/).  
* **PostgreSQL:** The database our server uses to keep track of user accounts and their public keys.

### **1\. Set Up the Database**

The server needs a place to store data. Let's get PostgreSQL ready.

* First, log in to psql and create a new user and database. Feel free to use a different username and password, but make sure it's secure\!  
  \-- Create a new user and database.  
  CREATE USER balsam\_user WITH PASSWORD 'your\_secure\_password';  
  CREATE DATABASE balsam\_db OWNER balsam\_user;

* Next, create the tables the server needs by running the schema.sql script. From your terminal, execute:  
  psql \-U balsam\_user \-d balsam\_db \-f server/schema.sql

  You'll be prompted for the password you just created.

### **2\. Configure the Server**

Now, let's tell our server how to connect to the database.

* In the server/ directory, create a file named .env.  
* Add the following configuration, making sure the DATABASE\_URL matches the credentials you set up.  
  \# server/.env  
  DATABASE\_URL=postgres://balsam\_user:your\_secure\_password@localhost/balsam\_db  
  SERVER\_DOMAIN=000196.xyz  
  SERVER\_ADDRESS=127.0.0.1:9600

### **3\. Build and Run**

With the setup complete, it's time to bring Balsam to life.

* **Build the project:** From the root directory, run the build command. Using the \--release flag is recommended for a faster, optimized build.  
  cargo build \--release

* **Run the Balsam Server:** In a terminal, start the server. It needs to stay running to handle connections.  
  cargo run \--release \--bin server

  You should see: Balsam Server listening on 127.0.0.1:9600.  
* **Run the Balsam Client:** Open a **new terminal window**. The first time you run the client, it will generate your unique cryptographic key and save it as balsam\_key.bin.  
  cargo run \--release \--bin client

  You'll see a message about your key and the client prompt \> .

## **How to Use Balsam**

The client gives you a few commands to interact with the network.

| Command | Description |
| :---- | :---- |
| register \<user\> | Creates your account on the server using your local private key. |
| login \<user\> | Authenticates your session with the server by proving ownership of your private key. |
| send \<user\!domain\> \<message\> | Sends an end-to-end encrypted message to the specified recipient. |
| inbox | Fetches all new messages, decrypts them with your private key, and displays them. |
| help | Displays a list of available commands and their usage. |
| quit | Exits the client application. |

### **Example Two-User Session**

To test a chat, you will need two separate client instances (in two separate terminals), as each client instance represents one user with one unique key.

1. **Start the server.**  
2. **In Terminal A (User 1):**  
   * Run cargo run \--release \--bin client. A key balsam\_key.bin is generated.  
   * \> register alice  
   * \> login alice  
3. **In Terminal B (User 2):**  
   * **Important:** Delete the balsam\_key.bin file created for User 1\.  
   * Run cargo run \--release \--bin client. A new, unique key is generated for User 2\.  
   * \> register bob  
   * \> login bob  
   * \> send alice\!000196.xyz Hello from Bob.  
4. **Return to Terminal A:**  
   * \> inbox  
   * The message from Bob will appear, decrypted.

## **Protocol Specification (Advanced)**

For developers interested in interoperability or the low-level design, the Balsam protocol adheres to the following specification.

### **Packet Framing**

All data is transmitted in frames with a fixed header structure.

| Field | Size (bytes) | Description |
| :---- | :---- | :---- |
| Magic Bytes | 4 | 0xAE 0x74 0x68 0x72 (Æthr) |
| Version | 1 | Protocol version (current: 0x01). |
| OpCode | 1 | The command identifier. |
| Payload Length | 4 | u32 length of the payload (Big Endian). |
| Payload | Variable | Data serialized with bincode. |
| Checksum | 4 | CRC32 of the payload for integrity. |

### **Opcodes**

| OpCode | Name | Direction | Description |
| :---- | :---- | :---- | :---- |
| 0x01 | SYN | C \-\> S | Client initiates handshake. |
| 0x02 | ACK | S \-\> C | Server acknowledges handshake. |
| 0x10 | REGISTER | C \-\> S | Register a new user with a public key. |
| 0x11 | AUTH\_REQ | C \-\> S | Request to begin authentication for a user. |
| 0x12 | AUTH\_CHALLENGE | S \-\> C | Server sends a random nonce to be signed. |
| 0x13 | AUTH\_RESPONSE | C \-\> S | Client returns the signed nonce. |
| 0x20 | FETCH\_PKEY | C \-\> S | Request the public key of another user. |
| 0x21 | PKEY\_RESPONSE | S \-\> C | Server returns the requested public key. |
| 0x30 | SEND\_MSG | C \-\> S | Send an end-to-end encrypted message blob. |
| 0x40 | FETCH\_INBOX | C \-\> S | Request all message blobs for the logged-in user. |
| 0x41 | INBOX\_RESPONSE | S \-\> C | Server returns a list of encrypted message blobs. |
| 0xFE | OK | S \-\> C | A generic success response. |
| 0xFF | ERROR | S \-\> C | A generic error occurred. |

## 