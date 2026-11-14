CREATE TABLE IF NOT EXISTS schema_versions(version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS accounts(
 id TEXT PRIMARY KEY, login_name TEXT NOT NULL, login_normalized TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL DEFAULT 'active', created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS profiles(
 uuid TEXT PRIMARY KEY, account_id TEXT NOT NULL UNIQUE REFERENCES accounts(id),
 name TEXT NOT NULL, name_normalized TEXT NOT NULL UNIQUE, skin_hash TEXT,
 skin_model TEXT NOT NULL DEFAULT 'default', last_renamed_at INTEGER);
CREATE TABLE IF NOT EXISTS identities(
 account_id TEXT NOT NULL UNIQUE REFERENCES accounts(id), app_id TEXT NOT NULL,
 group_id TEXT NOT NULL, member_id TEXT NOT NULL, UNIQUE(app_id,group_id,member_id));
CREATE TABLE IF NOT EXISTS registrations(
 id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, poll_hash TEXT NOT NULL,
 name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING',
 expires_at INTEGER NOT NULL, account_id TEXT REFERENCES accounts(id), error TEXT,
 session_issued INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS receipts(
 app_id TEXT NOT NULL, event_id TEXT NOT NULL, operation TEXT NOT NULL,
 payload_hash TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(app_id,event_id,operation));
CREATE TABLE IF NOT EXISTS tokens(
 hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), kind TEXT NOT NULL,
 client_token TEXT, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS joins(
 profile_id TEXT NOT NULL REFERENCES profiles(uuid), server_id TEXT NOT NULL,
 expires_at INTEGER NOT NULL, PRIMARY KEY(profile_id,server_id));
CREATE TABLE IF NOT EXISTS login_requests(
 id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, poll_hash TEXT NOT NULL,
 account_id TEXT REFERENCES accounts(id), status TEXT NOT NULL DEFAULT 'PENDING', expires_at INTEGER NOT NULL,
 session_issued INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY, action TEXT NOT NULL, account_id TEXT, detail TEXT, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS token_expiry ON tokens(expires_at);
CREATE INDEX IF NOT EXISTS registration_expiry ON registrations(expires_at);
CREATE TABLE IF NOT EXISTS refresh_retries(
 old_hash TEXT PRIMARY KEY, request_hash TEXT NOT NULL, nonce TEXT NOT NULL,
 game_hash TEXT NOT NULL REFERENCES tokens(hash) ON DELETE CASCADE,
 refresh_hash TEXT NOT NULL REFERENCES tokens(hash) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS login_retries(
 request_id TEXT PRIMARY KEY, poll_hash TEXT NOT NULL, request_hash TEXT NOT NULL, nonce TEXT NOT NULL,
 game_hash TEXT NOT NULL REFERENCES tokens(hash) ON DELETE CASCADE,
 refresh_hash TEXT NOT NULL REFERENCES tokens(hash) ON DELETE CASCADE,
 management_hash TEXT NOT NULL REFERENCES tokens(hash) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL);
