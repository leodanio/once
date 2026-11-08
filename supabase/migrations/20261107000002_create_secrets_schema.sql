-- ============================================================================
-- ONCE — End-to-End Encrypted Secrets Schema, RLS & Atomic Consumption RPCs
-- Migration: 20261107000002_create_secrets_schema.sql
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- 1. SECRETS TABLE
-- ----------------------------------------------------------------------------
-- Stores ONLY client-encrypted ciphertext and non-sensitive KDF/AEAD parameters.
-- Decryption keys and user passwords NEVER reach the server or database.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.secrets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token TEXT UNIQUE NOT NULL,
  ciphertext TEXT NOT NULL,
  iv TEXT NOT NULL,
  password_protected BOOLEAN NOT NULL DEFAULT FALSE,
  kdf_salt TEXT NULL,
  kdf_iterations INTEGER NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NULL,
  is_consumed BOOLEAN NOT NULL DEFAULT FALSE,
  consumed_at TIMESTAMPTZ NULL,

  CONSTRAINT secrets_token_format_chk
    CHECK (token ~ '^[a-zA-Z0-9_-]{16,64}$'),
  CONSTRAINT secrets_ciphertext_length_chk
    CHECK (char_length(ciphertext) BETWEEN 10 AND 16384),
  CONSTRAINT secrets_iv_format_chk
    CHECK (iv ~ '^[A-Za-z0-9_-]{16,32}$'),
  CONSTRAINT secrets_kdf_params_consistency_chk
    CHECK (
      (
        password_protected = FALSE
        AND kdf_salt IS NULL
        AND kdf_iterations IS NULL
      )
      OR (
        password_protected = TRUE
        AND kdf_salt IS NOT NULL
        AND kdf_salt ~ '^[A-Za-z0-9_-]{16,64}$'
        AND kdf_iterations IS NOT NULL
        AND kdf_iterations BETWEEN 100000 AND 1000000
      )
    ),
  CONSTRAINT secrets_consumed_state_consistency_chk
    CHECK (
      (is_consumed = FALSE AND consumed_at IS NULL)
      OR (is_consumed = TRUE AND consumed_at IS NOT NULL)
    )
);

-- Indexes for lookup and expiration maintenance
CREATE INDEX IF NOT EXISTS idx_secrets_expires_at
  ON public.secrets (expires_at)
  WHERE expires_at IS NOT NULL AND is_consumed = FALSE;

CREATE INDEX IF NOT EXISTS idx_secrets_created_at
  ON public.secrets (created_at DESC);

-- Enable and enforce Row Level Security
ALTER TABLE public.secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.secrets FORCE ROW LEVEL SECURITY;

-- Do not expose public.secrets to anonymous or authenticated direct reads/writes.
-- All database operations happen server-side via service_role.
REVOKE ALL ON TABLE public.secrets FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.secrets TO service_role;

-- ----------------------------------------------------------------------------
-- 2. NON-CONSUMING SECRET METADATA FUNCTION
-- ----------------------------------------------------------------------------
-- Checks availability and whether a password is required for key derivation
-- without consuming the secret or exposing ciphertext/IV/salt.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.get_secret_metadata(p_token TEXT)
RETURNS TABLE (
  status TEXT,
  password_protected BOOLEAN,
  expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public
AS $$
DECLARE
  v_secret public.secrets%ROWTYPE;
  v_now TIMESTAMPTZ := NOW();
BEGIN
  IF p_token IS NULL OR btrim(p_token) = '' THEN
    RETURN QUERY SELECT
      'not_found'::TEXT,
      FALSE::BOOLEAN,
      NULL::TIMESTAMPTZ;
    RETURN;
  END IF;

  SELECT *
  INTO v_secret
  FROM public.secrets s
  WHERE s.token = p_token;

  IF NOT FOUND THEN
    RETURN QUERY SELECT
      'not_found'::TEXT,
      FALSE::BOOLEAN,
      NULL::TIMESTAMPTZ;
    RETURN;
  END IF;

  IF v_secret.is_consumed OR v_secret.consumed_at IS NOT NULL THEN
    RETURN QUERY SELECT
      'consumed'::TEXT,
      FALSE::BOOLEAN,
      v_secret.expires_at;
    RETURN;
  END IF;

  IF v_secret.expires_at IS NOT NULL AND v_secret.expires_at <= v_now THEN
    RETURN QUERY SELECT
      'expired'::TEXT,
      FALSE::BOOLEAN,
      v_secret.expires_at;
    RETURN;
  END IF;

  RETURN QUERY SELECT
    'available'::TEXT,
    v_secret.password_protected,
    v_secret.expires_at;
END;
$$;

REVOKE ALL ON FUNCTION public.get_secret_metadata(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.get_secret_metadata(TEXT) TO service_role;

-- ----------------------------------------------------------------------------
-- 3. ATOMIC SECRET CONSUMPTION FUNCTION
-- ----------------------------------------------------------------------------
-- Atomically consumes a secret using row-level locking (FOR UPDATE), marks it
-- as consumed, overwrites the stored ciphertext, and returns the ciphertext
-- and KDF parameters to the single winning caller.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.consume_secret(p_token TEXT)
RETURNS TABLE (
  status TEXT,
  ciphertext TEXT,
  iv TEXT,
  password_protected BOOLEAN,
  kdf_salt TEXT,
  kdf_iterations INTEGER,
  expires_at TIMESTAMPTZ,
  consumed_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public
AS $$
DECLARE
  v_secret public.secrets%ROWTYPE;
  v_original_ciphertext TEXT;
  v_now TIMESTAMPTZ := NOW();
BEGIN
  IF p_token IS NULL OR btrim(p_token) = '' THEN
    RETURN QUERY SELECT
      'not_found'::TEXT,
      NULL::TEXT,
      NULL::TEXT,
      FALSE::BOOLEAN,
      NULL::TEXT,
      NULL::INTEGER,
      NULL::TIMESTAMPTZ,
      NULL::TIMESTAMPTZ;
    RETURN;
  END IF;

  -- Acquire an exclusive row-level lock on the target secret record.
  -- Concurrent requests for the same token serialize at this lock.
  SELECT *
  INTO v_secret
  FROM public.secrets s
  WHERE s.token = p_token
  FOR UPDATE;

  -- 1. Secret does not exist
  IF NOT FOUND THEN
    RETURN QUERY SELECT
      'not_found'::TEXT,
      NULL::TEXT,
      NULL::TEXT,
      FALSE::BOOLEAN,
      NULL::TEXT,
      NULL::INTEGER,
      NULL::TIMESTAMPTZ,
      NULL::TIMESTAMPTZ;
    RETURN;
  END IF;

  -- 2. Secret has already been consumed
  IF v_secret.is_consumed OR v_secret.consumed_at IS NOT NULL THEN
    RETURN QUERY SELECT
      'consumed'::TEXT,
      NULL::TEXT,
      NULL::TEXT,
      FALSE::BOOLEAN,
      NULL::TEXT,
      NULL::INTEGER,
      v_secret.expires_at,
      v_secret.consumed_at;
    RETURN;
  END IF;

  -- 3. Secret has passed its time-based expiration
  IF v_secret.expires_at IS NOT NULL AND v_secret.expires_at <= v_now THEN
    RETURN QUERY SELECT
      'expired'::TEXT,
      NULL::TEXT,
      NULL::TEXT,
      FALSE::BOOLEAN,
      NULL::TEXT,
      NULL::INTEGER,
      v_secret.expires_at,
      NULL::TIMESTAMPTZ;
    RETURN;
  END IF;

  v_original_ciphertext := v_secret.ciphertext;

  -- 4. Atomically mark as consumed and scrub stored ciphertext
  UPDATE public.secrets s
  SET
    is_consumed = TRUE,
    consumed_at = v_now,
    ciphertext = '[CONSUMED]'
  WHERE s.id = v_secret.id
    AND s.is_consumed = FALSE
    AND s.consumed_at IS NULL
    AND (s.expires_at IS NULL OR s.expires_at > v_now)
  RETURNING * INTO v_secret;

  IF NOT FOUND THEN
    RETURN QUERY SELECT
      'consumed'::TEXT,
      NULL::TEXT,
      NULL::TEXT,
      FALSE::BOOLEAN,
      NULL::TEXT,
      NULL::INTEGER,
      v_secret.expires_at,
      v_secret.consumed_at;
    RETURN;
  END IF;

  RETURN QUERY SELECT
    'valid'::TEXT,
    v_original_ciphertext,
    v_secret.iv,
    v_secret.password_protected,
    v_secret.kdf_salt,
    v_secret.kdf_iterations,
    v_secret.expires_at,
    v_secret.consumed_at;
END;
$$;

REVOKE ALL ON FUNCTION public.consume_secret(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_secret(TEXT) TO service_role;
