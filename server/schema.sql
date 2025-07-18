DROP TABLE IF EXISTS users, messages;

CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    public_key BYTEA NOT NULL
);

CREATE TABLE messages (
    id UUID PRIMARY KEY,
    recipient VARCHAR(255) NOT NULL,
    sender_pkey BYTEA NOT NULL,
    encrypted_blob BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);