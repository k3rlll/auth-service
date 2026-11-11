-- +goose Up
CREATE TABLE users (
    id                  TEXT PRIMARY KEY,
    email               TEXT        NOT NULL,
    username            TEXT        NOT NULL,
    password_hash       TEXT        NOT NULL,
    failed_logins       INT         NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL
);

-- Регистр не важен: Alice@Mail.ru и alice@mail.ru - один пользователь
CREATE UNIQUE INDEX users_email_key ON users (lower(email));
CREATE UNIQUE INDEX users_username_key ON users (lower(username));

CREATE TABLE sessions (
    id            TEXT PRIMARY KEY,
    user_id       TEXT        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_name   TEXT        NOT NULL,
    device_type   TEXT        NOT NULL,
    user_agent    TEXT        NOT NULL DEFAULT '',
    ip            TEXT        NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL,
    last_used_at  TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ,
    revoke_reason TEXT
);

-- Список активных устройств пользователя
CREATE INDEX sessions_user_active ON sessions (user_id, last_used_at DESC) WHERE revoked_at IS NULL;

CREATE TABLE refresh_tokens (
    token_hash BYTEA PRIMARY KEY,
    session_id TEXT        NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ
);

CREATE INDEX refresh_tokens_session ON refresh_tokens (session_id);
CREATE INDEX refresh_tokens_expires ON refresh_tokens (expires_at);

-- +goose Down
DROP TABLE refresh_tokens;
DROP TABLE sessions;
DROP TABLE users;
