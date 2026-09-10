ALTER TABLE users
ADD COLUMN IF NOT EXISTS mfa_pending_secret TEXT;
