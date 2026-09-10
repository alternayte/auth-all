===== 20260101000000_authall_core.sql =====
-- 20260101000000_authall_core
-- Owner: core
-- +goose Up
-- table:auth_oauth_states
CREATE TABLE IF NOT EXISTS auth_oauth_states (
    id TEXT NOT NULL PRIMARY KEY,
    state_hash TEXT NOT NULL,
    provider TEXT NOT NULL,
    verifier TEXT NOT NULL,
    nonce TEXT NOT NULL,
    redirect_to TEXT NOT NULL,
    link_user_id TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

-- index:auth_oauth_states_state_hash_key
CREATE UNIQUE INDEX IF NOT EXISTS auth_oauth_states_state_hash_key ON auth_oauth_states (state_hash);

-- table:auth_users
CREATE TABLE IF NOT EXISTS auth_users (
    id TEXT NOT NULL PRIMARY KEY,
    email TEXT NOT NULL,
    email_normalized TEXT NOT NULL,
    email_verified_at TEXT,
    display_name TEXT NOT NULL,
    image_url TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- index:auth_users_email_normalized_key
CREATE UNIQUE INDEX IF NOT EXISTS auth_users_email_normalized_key ON auth_users (email_normalized);

-- table:auth_accounts
CREATE TABLE IF NOT EXISTS auth_accounts (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_account_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
);

-- index:auth_accounts_provider_key
CREATE UNIQUE INDEX IF NOT EXISTS auth_accounts_provider_key ON auth_accounts (provider, provider_account_id);

-- index:auth_accounts_user_provider_key
CREATE UNIQUE INDEX IF NOT EXISTS auth_accounts_user_provider_key ON auth_accounts (user_id, provider);

-- table:auth_credentials
CREATE TABLE IF NOT EXISTS auth_credentials (
    user_id TEXT NOT NULL PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
);

-- table:auth_sessions
CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
);

-- index:auth_sessions_token_hash_key
CREATE UNIQUE INDEX IF NOT EXISTS auth_sessions_token_hash_key ON auth_sessions (token_hash);

-- index:auth_sessions_user_id_idx
CREATE INDEX IF NOT EXISTS auth_sessions_user_id_idx ON auth_sessions (user_id);

-- table:auth_tokens
CREATE TABLE IF NOT EXISTS auth_tokens (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT,
    kind TEXT NOT NULL,
    identifier TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
);

-- index:auth_tokens_kind_hash_key
CREATE UNIQUE INDEX IF NOT EXISTS auth_tokens_kind_hash_key ON auth_tokens (kind, token_hash);

-- index:auth_tokens_kind_identifier_idx
CREATE INDEX IF NOT EXISTS auth_tokens_kind_identifier_idx ON auth_tokens (kind, identifier);

-- table:auth_totp
CREATE TABLE IF NOT EXISTS auth_totp (
    user_id TEXT NOT NULL PRIMARY KEY,
    secret TEXT NOT NULL,
    confirmed_at TEXT,
    last_step INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
);

-- table:auth_totp_recovery
CREATE TABLE IF NOT EXISTS auth_totp_recovery (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
);

-- index:auth_totp_recovery_code_hash_key
CREATE UNIQUE INDEX IF NOT EXISTS auth_totp_recovery_code_hash_key ON auth_totp_recovery (code_hash);

-- index:auth_totp_recovery_user_idx
CREATE INDEX IF NOT EXISTS auth_totp_recovery_user_idx ON auth_totp_recovery (user_id);


-- +goose Down
-- drop-table:auth_totp_recovery
DROP TABLE IF EXISTS auth_totp_recovery;

-- drop-table:auth_totp
DROP TABLE IF EXISTS auth_totp;

-- drop-table:auth_tokens
DROP TABLE IF EXISTS auth_tokens;

-- drop-table:auth_sessions
DROP TABLE IF EXISTS auth_sessions;

-- drop-table:auth_credentials
DROP TABLE IF EXISTS auth_credentials;

-- drop-table:auth_accounts
DROP TABLE IF EXISTS auth_accounts;

-- drop-table:auth_users
DROP TABLE IF EXISTS auth_users;

-- drop-table:auth_oauth_states
DROP TABLE IF EXISTS auth_oauth_states;

===== 20260910000001_authall_user_admin_columns.sql =====
-- 20260910000001_authall_user_admin_columns
-- Owner: core
-- +goose Up
-- column:auth_users.role
ALTER TABLE auth_users ADD COLUMN role TEXT NOT NULL DEFAULT '';

-- column:auth_users.disabled_at
ALTER TABLE auth_users ADD COLUMN disabled_at TEXT;

-- column:auth_users.must_change_password
ALTER TABLE auth_users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;

-- index:auth_users_role_idx
CREATE INDEX IF NOT EXISTS auth_users_role_idx ON auth_users (role);


-- +goose Down
-- drop-index:auth_users_role_idx
DROP INDEX IF EXISTS auth_users_role_idx;

-- drop-column:auth_users.must_change_password
ALTER TABLE auth_users DROP COLUMN must_change_password;

-- drop-column:auth_users.disabled_at
ALTER TABLE auth_users DROP COLUMN disabled_at;

-- drop-column:auth_users.role
ALTER TABLE auth_users DROP COLUMN role;

