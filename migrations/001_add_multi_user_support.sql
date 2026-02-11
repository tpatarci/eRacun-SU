-- Migration: Add Multi-User Support
-- Description: Creates users and user_configurations tables, adds user_id foreign key to invoices
--
-- This migration enables multi-tenancy by:
-- 1. Creating a users table for authentication
-- 2. Creating a user_configurations table for per-user service credentials
-- 3. Adding user_id to invoices for data isolation
-- 4. Creating proper indexes and constraints
--
-- Usage: psql -h localhost -U eracun -d eracun -f migrations/001_add_multi_user_support.sql
--
-- To verify migration was applied:
-- SELECT COUNT(*) FROM users;
-- SELECT COUNT(*) FROM user_configurations;
-- \d invoices

-- ============================================================================
-- USERS TABLE
-- ============================================================================
-- Stores user authentication and profile information
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  name VARCHAR(255),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

-- Index for email lookups during authentication
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ============================================================================
-- USER_CONFIGURATIONS TABLE
-- ============================================================================
-- Stores per-user service configuration (FINA, IMAP credentials)
CREATE TABLE IF NOT EXISTS user_configurations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  service_name VARCHAR(50) NOT NULL,
  config JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT valid_service_name CHECK (service_name IN ('fina', 'imap')),
  UNIQUE(user_id, service_name)
);

-- Index for user config lookups
CREATE INDEX IF NOT EXISTS idx_user_configurations_user_id ON user_configurations(user_id);

-- Index for service name queries
CREATE INDEX IF NOT EXISTS idx_user_configurations_service_name ON user_configurations(service_name);

-- ============================================================================
-- INVOICES TABLE - ADD USER_ID COLUMN
-- ============================================================================
-- Add user_id foreign key to invoices for data isolation
-- Initially nullable to allow for data migration from existing single-user deployments
DO $$
BEGIN
  -- Only add column if it doesn't exist
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'invoices' AND column_name = 'user_id'
  ) THEN
    ALTER TABLE invoices ADD COLUMN user_id UUID REFERENCES users(id);
  END IF;
END $$;

-- Create index on user_id for efficient filtering
CREATE INDEX IF NOT EXISTS idx_invoices_user_id ON invoices(user_id);

-- ============================================================================
-- UNIQUE CONSTRAINT UPDATE FOR INVOICES
-- ============================================================================
-- Update unique constraint to allow same OIB+invoice_number for different users
-- This enables multiple business entities to issue invoices with same numbers
--
-- Note: If a unique constraint on (oib, invoice_number) exists, it needs to be
-- updated to include user_id. This is typically done in a follow-up data migration
-- after existing data has been assigned to a default user.
--
-- For new deployments with no data, you can use:
-- ALTER TABLE invoices DROP CONSTRAINT IF EXISTS invoices_oib_invoice_number_key;
-- ALTER TABLE invoices ADD CONSTRAINT invoices_oib_invoice_number_user_id_key
--   UNIQUE (oib, invoice_number, user_id);
--
-- For existing deployments, see migration 002_migrate_existing_data.sql

-- ============================================================================
-- MIGRATION NOTES
-- ============================================================================
--
-- For EXISTING DEPLOYMENTS with data:
--
-- 1. Create a default user to own existing invoice data:
--    INSERT INTO users (email, password_hash, name)
--    VALUES ('migrated@local', '$2b$12$placeholderHashReplaceWithRealHash', 'Migrated User');
--
-- 2. Update existing invoices to belong to the default user:
--    UPDATE invoices
--    SET user_id = (SELECT id FROM users WHERE email = 'migrated@local')
--    WHERE user_id IS NULL;
--
-- 3. Make user_id NOT NULL (after data migration):
--    ALTER TABLE invoices ALTER COLUMN user_id SET NOT NULL;
--    ALTER TABLE invoices ADD CONSTRAINT invoices_oib_invoice_number_user_id_key
--      UNIQUE (oib, invoice_number, user_id);
--
-- 4. Migrate existing environment-based FINA/IMAP config to database (optional)
--
-- See migration 002_migrate_existing_data.sql for automated data migration.
--
-- For NEW DEPLOYMENTS:
--
-- If this is a fresh deployment with no existing invoice data, you can
-- immediately make user_id NOT NULL and add the updated unique constraint:
--
--   ALTER TABLE invoices ALTER COLUMN user_id SET NOT NULL;
--   ALTER TABLE invoices ADD CONSTRAINT invoices_oib_invoice_number_user_id_key
--     UNIQUE (oib, invoice_number, user_id);

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================
-- Run these queries to verify the migration was successful:
--
-- \d users                    -- Verify users table structure
-- \d user_configurations      -- Verify user_configurations table structure
-- \d invoices                 -- Verify invoices has user_id column
-- \d+ invoices                -- Check indexes on invoices table
--
-- SELECT COUNT(*) FROM users;                    -- Should return 0 for new deployment
-- SELECT COUNT(*) FROM user_configurations;      -- Should return 0 for new deployment
--
-- -- Verify index exists
-- SELECT indexname FROM pg_indexes WHERE tablename = 'invoices' AND indexname = 'idx_invoices_user_id';
--
-- -- Verify foreign key constraint exists
-- SELECT constraint_name
-- FROM information_schema.table_constraints
-- WHERE table_name = 'invoices' AND constraint_type = 'FOREIGN KEY';

-- Migration completed successfully
