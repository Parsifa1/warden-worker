-- Split passkey login credentials from WebAuthn 2FA credentials.
-- Run once on production.

CREATE TABLE IF NOT EXISTS two_factor_webauthn_settings (
    user_id TEXT PRIMARY KEY NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

ALTER TABLE two_factor_webauthn
ADD COLUMN credential_use TEXT NOT NULL DEFAULT 'both';

UPDATE two_factor_webauthn
SET credential_use = CASE
    WHEN COALESCE(encrypted_public_key, '') <> ''
      OR COALESCE(encrypted_user_key, '') <> ''
      OR COALESCE(encrypted_private_key, '') <> ''
    THEN 'login'
    ELSE '2fa'
END
WHERE credential_use = 'both' OR credential_use IS NULL OR credential_use = '';
