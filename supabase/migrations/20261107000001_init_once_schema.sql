-- ============================================================================
-- ONCE — Database Schema, RLS Policies, Atomic Consumption & Rate Limiting
-- Migration: 20261107000001_init_once_schema.sql
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- 1. LINKS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.links (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug TEXT UNIQUE NOT NULL,
  destination_url TEXT NOT NULL,
  custom_message TEXT NULL,
  max_views INTEGER NOT NULL DEFAULT 1,
  views_count INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  used_at TIMESTAMPTZ NULL,

  CONSTRAINT links_slug_format_chk
    CHECK (slug ~ '^[a-zA-Z0-9_-]{3,32}$'),
  CONSTRAINT links_destination_url_length_chk
    CHECK (char_length(destination_url) BETWEEN 1 AND 2048),
  CONSTRAINT links_destination_protocol_chk
    CHECK (destination_url ~* '^https?://'),
  CONSTRAINT links_custom_message_length_chk
    CHECK (custom_message IS NULL OR char_length(custom_message) <= 140),
  CONSTRAINT links_max_views_range_chk
    CHECK (max_views >= 1 AND max_views <= 1000),
  CONSTRAINT links_views_count_non_negative_chk
    CHECK (views_count >= 0),
  CONSTRAINT links_views_count_lte_max_views_chk
    CHECK (views_count <= max_views)
);

-- Indexes for fast lookup and expiration maintenance
CREATE INDEX IF NOT EXISTS idx_links_expires_at
  ON public.links (expires_at)
  WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_links_created_at
  ON public.links (created_at DESC);

-- Enable and enforce Row Level Security
ALTER TABLE public.links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.links FORCE ROW LEVEL SECURITY;

-- Do not expose public.links to anonymous or authenticated direct reads/writes.
-- All database operations happen server-side via service_role.
REVOKE ALL ON TABLE public.links FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.links TO service_role;

-- ----------------------------------------------------------------------------
-- 2. PERSISTENT RATE LIMITING TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.rate_limits (
  key TEXT PRIMARY KEY,
  request_count INTEGER NOT NULL DEFAULT 1,
  window_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT rate_limits_request_count_positive_chk
    CHECK (request_count >= 1)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_window_start
  ON public.rate_limits (window_start);

ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rate_limits FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.rate_limits FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.rate_limits TO service_role;

-- ----------------------------------------------------------------------------
-- 3. ATOMIC LINK CONSUMPTION FUNCTION
-- ----------------------------------------------------------------------------
-- Consumes a single view of a link atomically using row-level locking (FOR UPDATE).
-- Two simultaneous requests can NEVER both consume the final available view.
-- Uses SECURITY INVOKER and restricts EXECUTE exclusively to service_role.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.consume_link(p_slug TEXT)
RETURNS TABLE (
  status TEXT,
  destination_url TEXT,
  custom_message TEXT,
  views_count INTEGER,
  max_views INTEGER,
  expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public
AS $$
DECLARE
  v_link public.links%ROWTYPE;
  v_now TIMESTAMPTZ := NOW();
BEGIN
  IF p_slug IS NULL OR btrim(p_slug) = '' THEN
    RETURN QUERY SELECT
      'not_found'::TEXT,
      NULL::TEXT,
      NULL::TEXT,
      0::INTEGER,
      0::INTEGER,
      NULL::TIMESTAMPTZ;
    RETURN;
  END IF;

  -- Acquire an exclusive row-level lock on the target link record.
  -- Concurrent calls for the same slug will serialize at this lock.
  SELECT *
  INTO v_link
  FROM public.links l
  WHERE l.slug = p_slug
  FOR UPDATE;

  -- 1. Link does not exist
  IF NOT FOUND THEN
    RETURN QUERY SELECT
      'not_found'::TEXT,
      NULL::TEXT,
      NULL::TEXT,
      0::INTEGER,
      0::INTEGER,
      NULL::TIMESTAMPTZ;
    RETURN;
  END IF;

  -- 2. Link has passed its time-based expiration
  IF v_link.expires_at IS NOT NULL AND v_link.expires_at <= v_now THEN
    RETURN QUERY SELECT
      'expired'::TEXT,
      NULL::TEXT,
      v_link.custom_message,
      v_link.views_count,
      v_link.max_views,
      v_link.expires_at;
    RETURN;
  END IF;

  -- 3. Link has already reached its maximum allowed views
  IF v_link.views_count >= v_link.max_views THEN
    RETURN QUERY SELECT
      'max_views_reached'::TEXT,
      NULL::TEXT,
      v_link.custom_message,
      v_link.views_count,
      v_link.max_views,
      v_link.expires_at;
    RETURN;
  END IF;

  -- 4. Link is valid: atomically increment views_count and record used_at
  UPDATE public.links l
  SET
    views_count = l.views_count + 1,
    used_at = CASE
      WHEN l.views_count + 1 >= l.max_views THEN v_now
      ELSE COALESCE(l.used_at, v_now)
    END
  WHERE l.id = v_link.id
    AND l.views_count < l.max_views
    AND (l.expires_at IS NULL OR l.expires_at > v_now)
  RETURNING * INTO v_link;

  IF NOT FOUND THEN
    -- Defensive fallback in case constraint prevented update
    RETURN QUERY SELECT
      'expired'::TEXT,
      NULL::TEXT,
      v_link.custom_message,
      v_link.views_count,
      v_link.max_views,
      v_link.expires_at;
    RETURN;
  END IF;

  RETURN QUERY SELECT
    'valid'::TEXT,
    v_link.destination_url,
    v_link.custom_message,
    v_link.views_count,
    v_link.max_views,
    v_link.expires_at;
END;
$$;

REVOKE ALL ON FUNCTION public.consume_link(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_link(TEXT) TO service_role;

-- ----------------------------------------------------------------------------
-- 4. ATOMIC RATE LIMITING FUNCTION
-- ----------------------------------------------------------------------------
-- Persistent fixed-window rate limiter executed atomically inside PostgreSQL.
-- Safe across stateless serverless functions (e.g., Vercel).
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.check_rate_limit(
  p_key TEXT,
  p_max_requests INTEGER,
  p_window_seconds INTEGER
)
RETURNS TABLE (
  allowed BOOLEAN,
  current_count INTEGER,
  reset_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public
AS $$
DECLARE
  v_now TIMESTAMPTZ := NOW();
  v_window INTERVAL := make_interval(secs => p_window_seconds);
  v_record public.rate_limits%ROWTYPE;
BEGIN
  INSERT INTO public.rate_limits (key, request_count, window_start)
  VALUES (p_key, 1, v_now)
  ON CONFLICT (key) DO UPDATE
  SET
    request_count = CASE
      WHEN public.rate_limits.window_start + v_window <= v_now THEN 1
      ELSE public.rate_limits.request_count + 1
    END,
    window_start = CASE
      WHEN public.rate_limits.window_start + v_window <= v_now THEN v_now
      ELSE public.rate_limits.window_start
    END
  RETURNING * INTO v_record;

  RETURN QUERY SELECT
    (v_record.request_count <= p_max_requests) AS allowed,
    v_record.request_count AS current_count,
    (v_record.window_start + v_window) AS reset_at;
END;
$$;

REVOKE ALL ON FUNCTION public.check_rate_limit(TEXT, INTEGER, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.check_rate_limit(TEXT, INTEGER, INTEGER) TO service_role;
