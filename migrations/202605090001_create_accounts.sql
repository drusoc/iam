-- +goose Up
CREATE TABLE accounts (
    id BIGSERIAL PRIMARY KEY,
    google_sub TEXT NOT NULL,
    email TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT accounts_google_sub_key UNIQUE (google_sub),
    CONSTRAINT accounts_status_check CHECK (status IN ('active', 'blocked', 'deleted'))
);

CREATE INDEX accounts_status_idx ON accounts (status);

-- +goose Down
DROP TABLE accounts;
