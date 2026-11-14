CREATE TABLE IF NOT EXISTS schema_versions(version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS accounts(
 id VARCHAR(64) PRIMARY KEY, login_name VARCHAR(128) NOT NULL,
 login_normalized VARCHAR(128) NOT NULL UNIQUE,
 status VARCHAR(32) NOT NULL DEFAULT 'active', created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS profiles(
 uuid VARCHAR(64) PRIMARY KEY, account_id VARCHAR(64) NOT NULL UNIQUE,
 name VARCHAR(128) NOT NULL, name_normalized VARCHAR(128) NOT NULL UNIQUE, skin_hash VARCHAR(64),
 skin_model VARCHAR(32) NOT NULL DEFAULT 'default', last_renamed_at BIGINT,
 FOREIGN KEY(account_id) REFERENCES accounts(id));
CREATE TABLE IF NOT EXISTS identities(
 account_id VARCHAR(64) NOT NULL UNIQUE, app_id VARCHAR(128) NOT NULL,
 group_id VARCHAR(128) NOT NULL, member_id VARCHAR(128) NOT NULL,
 UNIQUE(app_id,group_id,member_id), FOREIGN KEY(account_id) REFERENCES accounts(id));
CREATE TABLE IF NOT EXISTS registrations(
 id VARCHAR(64) PRIMARY KEY, code_hash VARCHAR(64) NOT NULL UNIQUE, poll_hash VARCHAR(64) NOT NULL,
 name VARCHAR(128) NOT NULL, status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
 expires_at BIGINT NOT NULL, account_id VARCHAR(64), error TEXT,
 session_issued INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(account_id) REFERENCES accounts(id),
 INDEX registration_expiry(expires_at));
CREATE TABLE IF NOT EXISTS receipts(
 app_id VARCHAR(128) NOT NULL, event_id VARCHAR(256) NOT NULL, operation VARCHAR(32) NOT NULL,
 payload_hash VARCHAR(64) NOT NULL, result TEXT NOT NULL, created_at BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(app_id,event_id,operation), INDEX receipt_created(created_at));
CREATE TABLE IF NOT EXISTS tokens(
 hash VARCHAR(64) PRIMARY KEY, account_id VARCHAR(64) NOT NULL, kind VARCHAR(32) NOT NULL,
 client_token TEXT, expires_at BIGINT NOT NULL, FOREIGN KEY(account_id) REFERENCES accounts(id),
 INDEX token_expiry(expires_at));
CREATE TABLE IF NOT EXISTS joins(
 profile_id VARCHAR(64) NOT NULL, server_id VARCHAR(256) NOT NULL,
 expires_at BIGINT NOT NULL, PRIMARY KEY(profile_id,server_id),
 FOREIGN KEY(profile_id) REFERENCES profiles(uuid));
CREATE TABLE IF NOT EXISTS login_requests(
 id VARCHAR(64) PRIMARY KEY, code_hash VARCHAR(64) NOT NULL UNIQUE, poll_hash VARCHAR(64) NOT NULL,
 account_id VARCHAR(64), status VARCHAR(32) NOT NULL DEFAULT 'PENDING', expires_at BIGINT NOT NULL,
 session_issued INTEGER NOT NULL DEFAULT 0, app_id VARCHAR(128), group_id VARCHAR(128),
 member_id VARCHAR(128), error TEXT, FOREIGN KEY(account_id) REFERENCES accounts(id));
CREATE TABLE IF NOT EXISTS audit(
 id BIGINT AUTO_INCREMENT PRIMARY KEY, action TEXT NOT NULL, account_id VARCHAR(64),
 detail TEXT, created_at BIGINT NOT NULL, INDEX audit_created(created_at));
CREATE TABLE IF NOT EXISTS refresh_retries(
 old_hash VARCHAR(64) PRIMARY KEY, request_hash VARCHAR(64) NOT NULL, nonce TEXT NOT NULL,
 game_hash VARCHAR(64) NOT NULL, refresh_hash VARCHAR(64) NOT NULL, expires_at BIGINT NOT NULL,
 FOREIGN KEY(game_hash) REFERENCES tokens(hash) ON DELETE CASCADE,
 FOREIGN KEY(refresh_hash) REFERENCES tokens(hash) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS login_retries(
 request_id VARCHAR(64) PRIMARY KEY, poll_hash VARCHAR(64) NOT NULL, request_hash VARCHAR(64) NOT NULL,
 nonce TEXT NOT NULL, game_hash VARCHAR(64) NOT NULL, refresh_hash VARCHAR(64) NOT NULL,
 management_hash VARCHAR(64) NOT NULL, expires_at BIGINT NOT NULL,
 FOREIGN KEY(game_hash) REFERENCES tokens(hash) ON DELETE CASCADE,
 FOREIGN KEY(refresh_hash) REFERENCES tokens(hash) ON DELETE CASCADE,
 FOREIGN KEY(management_hash) REFERENCES tokens(hash) ON DELETE CASCADE);
