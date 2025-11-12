-- Admin Portal API Database Schema
-- PostgreSQL 14+

-- Create database (run as superuser)
-- CREATE DATABASE admin_portal;
-- \c admin_portal

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW(),
  last_login TIMESTAMP
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token VARCHAR(512) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON sessions(user_id, expires_at) WHERE expires_at > NOW();

-- Comments
COMMENT ON TABLE users IS 'Admin portal user accounts';
COMMENT ON TABLE sessions IS 'Active user sessions';
COMMENT ON COLUMN users.password_hash IS 'bcrypt hashed password (cost factor 12)';
COMMENT ON COLUMN users.role IS 'User role: admin (full access), operator (manual review), viewer (read-only)';
COMMENT ON COLUMN sessions.expires_at IS 'Session expiration timestamp (24 hours from creation)';
