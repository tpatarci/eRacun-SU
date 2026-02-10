-- Migration: Migrate Existing Data for Multi-User Support
-- Description: Migrates existing single-user deployment data to multi-user architecture
--
-- This migration handles existing deployments by:
-- 1. Creating a default user to own existing invoice data
-- 2. Assigning all existing invoices to the default user
-- 3. Making user_id NOT NULL after data migration
-- 4. Updating unique constraint to include user_id
-- 5. Migrating environment-based FINA/IMAP config to database (optional)
--
-- Prerequisites:
-- - Migration 001_add_multi_user_support.sql must be applied first
-- - For config migration: Set variables below or provide as parameters
--
-- Usage: psql -h localhost -U eracun -d eracun -f migrations/002_migrate_existing_data.sql
--
-- To verify migration was applied:
-- SELECT COUNT(*) FROM users WHERE email = 'migrated@local';
-- SELECT COUNT(*) FROM invoices WHERE user_id IS NULL;
-- \d invoices

-- ============================================================================
-- CONFIGURATION (Optional - for migrating environment-based config)
-- ============================================================================
-- Uncomment and set these values to migrate FINA/IMAP config from environment
-- DO NOT commit actual credentials to version control!

-- \set fina_wsdl_url ''
-- \set fina_cert_path ''
-- \set fina_cert_passphrase ''
-- \set imap_host ''
-- \set imap_port '993'
-- \set imap_user ''
-- \set imap_password ''

-- ============================================================================
-- STEP 1: CREATE DEFAULT USER FOR EXISTING DATA
-- ============================================================================
-- Creates a default user to own all existing invoice data from single-user deployment
--
-- IMPORTANT: The default password hash below is a bcrypt hash for 'ChangeMe123!'
-- Users should change this password immediately after first login via API

DO $$
DECLARE
  default_user_id UUID;
  user_count INTEGER;
BEGIN
  -- Check if default user already exists
  SELECT COUNT(*) INTO user_count FROM users WHERE email = 'migrated@local';

  IF user_count = 0 THEN
    -- Create default user with placeholder password (bcrypt hash for 'ChangeMe123!')
    -- Users MUST change this password after first login
    INSERT INTO users (email, password_hash, name)
    VALUES (
      'migrated@local',
      '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36UmNPnuZ8YlWNTvGEJNvLu',
      'Migrated User'
    )
    RETURNING id INTO default_user_id;

    RAISE NOTICE 'Created default user with email: migrated@local';
    RAISE NOTICE 'IMPORTANT: User should change password immediately after first login';
    RAISE NOTICE 'Default user ID: %', default_user_id;
  ELSE
    -- Default user already exists, get their ID
    SELECT id INTO default_user_id FROM users WHERE email = 'migrated@local';
    RAISE NOTICE 'Default user already exists with ID: %', default_user_id;
  END IF;
END $$;

-- ============================================================================
-- STEP 2: MIGRATE EXISTING INVOICES TO DEFAULT USER
-- ============================================================================
-- Assigns all existing invoices (where user_id is NULL) to the default user

DO $$
DECLARE
  default_user_id UUID;
  invoices_migrated INTEGER;
BEGIN
  -- Get default user ID
  SELECT id INTO default_user_id FROM users WHERE email = 'migrated@local';

  IF default_user_id IS NULL THEN
    RAISE EXCEPTION 'Default user not found. Please ensure Step 1 completed successfully.';
  END IF;

  -- Update invoices without user_id to belong to default user
  UPDATE invoices
  SET user_id = default_user_id
  WHERE user_id IS NULL;

  GET DIAGNOSTICS invoices_migrated = ROW_COUNT;
  RAISE NOTICE 'Migrated % invoices to default user', invoices_migrated;
END $$;

-- ============================================================================
-- STEP 3: MAKE USER_ID NOT NULL
-- ============================================================================
-- After data migration, make user_id mandatory to ensure all future invoices
-- are properly associated with a user

DO $$
BEGIN
  -- Only proceed if all invoices have user_id set
  IF NOT EXISTS (
    SELECT 1 FROM invoices WHERE user_id IS NULL LIMIT 1
  ) THEN
    ALTER TABLE invoices ALTER COLUMN user_id SET NOT NULL;
    RAISE NOTICE 'user_id column is now NOT NULL';
  ELSE
    RAISE EXCEPTION 'Cannot make user_id NOT NULL: some invoices still have NULL user_id';
  END IF;
END $$;

-- ============================================================================
-- STEP 4: UPDATE UNIQUE CONSTRAINT TO INCLUDE USER_ID
-- ============================================================================
-- Updates the unique constraint on (oib, invoice_number) to include user_id
-- This allows different users to have invoices with the same OIB and number

DO $$
DECLARE
  constraint_exists BOOLEAN;
BEGIN
  -- Check if old constraint exists
  SELECT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'invoices_oib_invoice_number_key'
  ) INTO constraint_exists;

  IF constraint_exists THEN
    -- Drop old constraint (oib, invoice_number only)
    ALTER TABLE invoices DROP CONSTRAINT IF EXISTS invoices_oib_invoice_number_key;
    RAISE NOTICE 'Dropped old unique constraint on (oib, invoice_number)';
  END IF;

  -- Create new constraint including user_id
  -- This allows same invoice number for different users
  ALTER TABLE invoices ADD CONSTRAINT invoices_oib_invoice_number_user_id_key
    UNIQUE (oib, invoice_number, user_id);

  RAISE NOTICE 'Added new unique constraint on (oib, invoice_number, user_id)';
END $$;

-- ============================================================================
-- STEP 5: MIGRATE ENVIRONMENT-BASED CONFIG (OPTIONAL)
-- ============================================================================
-- Migrates existing FINA and IMAP configuration from environment variables
-- to the database for the default user.
--
-- NOTE: This step is OPTIONAL and requires setting the variables above.
-- To skip this step, leave the variables empty or comment out the section.

DO $$
DECLARE
  default_user_id UUID;
  fina_wsdl_val TEXT := :'fina_wsdl_url';
  fina_cert_path_val TEXT := :'fina_cert_path';
  fina_cert_pass_val TEXT := :'fina_cert_passphrase';
  imap_host_val TEXT := :'imap_host';
  imap_port_val TEXT := :'imap_port';
  imap_user_val TEXT := :'imap_user';
  imap_pass_val TEXT := :'imap_password';
BEGIN
  -- Get default user ID
  SELECT id INTO default_user_id FROM users WHERE email = 'migrated@local';

  IF default_user_id IS NULL THEN
    RAISE EXCEPTION 'Default user not found. Cannot migrate config.';
  END IF;

  -- Migrate FINA config if values are provided
  IF fina_wsdl_val IS NOT NULL AND fina_wsdl_val != '' THEN
    INSERT INTO user_configurations (user_id, service_name, config)
    VALUES (
      default_user_id,
      'fina',
      jsonb_build_object(
        'wsdlUrl', fina_wsdl_val,
        'certPath', fina_cert_path_val,
        'certPassphrase', fina_cert_pass_val
      )
    )
    ON CONFLICT (user_id, service_name) DO UPDATE
    SET config = EXCLUDED.config, updated_at = NOW();

    RAISE NOTICE 'Migrated FINA configuration to database';
  ELSE
    RAISE NOTICE 'Skipping FINA config migration (values not provided)';
  END IF;

  -- Migrate IMAP config if values are provided
  IF imap_host_val IS NOT NULL AND imap_host_val != '' THEN
    INSERT INTO user_configurations (user_id, service_name, config)
    VALUES (
      default_user_id,
      'imap',
      jsonb_build_object(
        'host', imap_host_val,
        'port', CAST(imap_port_val AS INTEGER),
        'user', imap_user_val,
        'password', imap_pass_val
      )
    )
    ON CONFLICT (user_id, service_name) DO UPDATE
    SET config = EXCLUDED.config, updated_at = NOW();

    RAISE NOTICE 'Migrated IMAP configuration to database';
  ELSE
    RAISE NOTICE 'Skipping IMAP config migration (values not provided)';
  END IF;
END $$;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================
-- Run these queries to verify the migration was successful:

-- Check default user exists
-- SELECT id, email, name FROM users WHERE email = 'migrated@local';

-- Check all invoices have user_id set
-- SELECT COUNT(*) FROM invoices WHERE user_id IS NULL;
-- Expected: 0

-- Check invoice distribution by user
-- SELECT u.email, COUNT(i.id) as invoice_count
-- FROM users u
-- LEFT JOIN invoices i ON u.id = i.user_id
-- GROUP BY u.email;

-- Verify unique constraint includes user_id
-- SELECT conname, pg_get_constraintdef(oid)
-- FROM pg_constraint
-- WHERE conname = 'invoices_oib_invoice_number_user_id_key';

-- Check migrated configuration
-- SELECT service_name, config FROM user_configurations
-- WHERE user_id = (SELECT id FROM users WHERE email = 'migrated@local');

-- ============================================================================
-- POST-MIGRATION INSTRUCTIONS
-- ============================================================================
--
-- After running this migration:
--
-- 1. CHANGE THE DEFAULT PASSWORD:
--    The default user 'migrated@local' has password 'ChangeMe123!'
--    Use the API to change this immediately:
--
--    POST /api/v1/auth/login
--    { "email": "migrated@local", "password": "ChangeMe123!" }
--
--    Then implement a password change endpoint or update directly in database
--
-- 2. UPDATE CONFIGURATION:
--    If you skipped environment variable migration in Step 5, configure
--    FINA and IMAP settings via the API:
--
--    PUT /api/v1/users/me/config/fina
--    { "wsdlUrl": "...", "certPath": "...", "certPassphrase": "..." }
--
--    PUT /api/v1/users/me/config/imap
--    { "host": "...", "port": 993, "user": "...", "password": "..." }
--
-- 3. VERIFY APPLICATION FUNCTIONALITY:
--    - Test login with migrated user
--    - Verify existing invoices are accessible
--    - Test new invoice submission
--    - Verify configuration loading works
--
-- 4. (OPTIONAL) CREATE ADDITIONAL USERS:
--    Use the API to create additional users for team members or clients
--
-- ============================================================================
-- ROLLBACK INSTRUCTIONS
-- ============================================================================
--
-- If you need to rollback this migration (WARNING: this will lose user associations):
--
-- -- Drop unique constraint including user_id
-- ALTER TABLE invoices DROP CONSTRAINT IF EXISTS invoices_oib_invoice_number_user_id_key;
--
-- -- Restore original unique constraint (if it existed before)
-- -- Note: This may cause conflicts if duplicate (oib, invoice_number) now exist
-- ALTER TABLE invoices ADD CONSTRAINT invoices_oib_invoice_number_key
--   UNIQUE (oib, invoice_number);
--
-- -- Make user_id nullable again
-- ALTER TABLE invoices ALTER COLUMN user_id DROP NOT NULL;
--
-- -- Remove user_id from existing invoices
-- UPDATE invoices SET user_id = NULL;
--
-- -- Delete default user (this will cascade to user_configurations)
-- DELETE FROM users WHERE email = 'migrated@local';
--
-- ============================================================================

-- Migration completed successfully
