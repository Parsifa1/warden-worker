CREATE TABLE IF NOT EXISTS two_factor_webauthn (
    user_id TEXT NOT NULL,
    slot_id INTEGER NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    credential_id_b64url TEXT NOT NULL,
    public_key_cose_b64 TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, slot_id),
    UNIQUE (user_id, credential_id_b64url),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    user_id TEXT PRIMARY KEY NOT NULL,
    challenge_b64url TEXT NOT NULL,
    challenge_type TEXT NOT NULL,
    rp_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_two_factor_webauthn_user_id ON two_factor_webauthn(user_id);
