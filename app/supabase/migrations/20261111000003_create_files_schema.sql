-- ============================================================================
-- ONCE — Database Schema, RLS Policies, Atomic Challenge & Storage Management
-- Migration: 20261111000003_create_files_schema.sql
-- ============================================================================

-- Ensure pgcrypto is available
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- 1. FILE TRANSFERS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.file_transfers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transfer_token TEXT NOT NULL UNIQUE,
    storage_path TEXT NOT NULL UNIQUE,
    encrypted_meta JSONB NOT NULL,
    pop_public_key_spki TEXT NOT NULL,
    max_downloads INTEGER NOT NULL DEFAULT 1,
    download_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('pending_upload', 'ready', 'completed', 'expired', 'deleted')) DEFAULT 'pending_upload',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    used_at TIMESTAMPTZ NULL,

    CONSTRAINT file_transfers_token_fmt_chk CHECK (transfer_token ~ '^[a-zA-Z0-9_-]{16,64}$'),
    CONSTRAINT file_transfers_max_downloads_chk CHECK (max_downloads >= 1 AND max_downloads <= 100),
    CONSTRAINT file_transfers_download_count_chk CHECK (download_count >= 0 AND download_count <= max_downloads)
);

CREATE INDEX IF NOT EXISTS idx_file_transfers_token ON public.file_transfers (transfer_token);
CREATE INDEX IF NOT EXISTS idx_file_transfers_status ON public.file_transfers (status);
CREATE INDEX IF NOT EXISTS idx_file_transfers_expires_at ON public.file_transfers (expires_at);

ALTER TABLE public.file_transfers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.file_transfers FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.file_transfers FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.file_transfers TO service_role;

-- ----------------------------------------------------------------------------
-- 2. DOWNLOAD CHALLENGES TABLE (Proof of Possession)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.download_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID NOT NULL REFERENCES public.file_transfers(id) ON DELETE CASCADE,
    client_ip TEXT NOT NULL,
    challenge_nonce BYTEA NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'consumed', 'expired')) DEFAULT 'pending',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    consumed_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_download_challenges_file_id ON public.download_challenges (file_id);
CREATE INDEX IF NOT EXISTS idx_download_challenges_status ON public.download_challenges (status);
CREATE INDEX IF NOT EXISTS idx_download_challenges_expires_at ON public.download_challenges (expires_at);

ALTER TABLE public.download_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.download_challenges FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.download_challenges FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.download_challenges TO service_role;

-- ----------------------------------------------------------------------------
-- 3. FILE REQUESTS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.file_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_token TEXT NOT NULL UNIQUE,
    owner_token_hash TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    creator_public_key_spki TEXT NOT NULL,
    max_files INTEGER NOT NULL DEFAULT 5,
    max_bytes_per_file BIGINT NOT NULL DEFAULT 47185920, -- 45 MB
    files_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('active', 'closed', 'expired')) DEFAULT 'active',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    closed_at TIMESTAMPTZ NULL,

    CONSTRAINT file_requests_token_fmt_chk CHECK (request_token ~ '^[a-zA-Z0-9_-]{16,64}$'),
    CONSTRAINT file_requests_max_files_chk CHECK (max_files >= 1 AND max_files <= 50),
    CONSTRAINT file_requests_files_count_chk CHECK (files_count >= 0 AND files_count <= max_files)
);

CREATE INDEX IF NOT EXISTS idx_file_requests_token ON public.file_requests (request_token);
CREATE INDEX IF NOT EXISTS idx_file_requests_owner_hash ON public.file_requests (owner_token_hash);
CREATE INDEX IF NOT EXISTS idx_file_requests_status ON public.file_requests (status);

ALTER TABLE public.file_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.file_requests FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.file_requests FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.file_requests TO service_role;

-- ----------------------------------------------------------------------------
-- 4. FILE REQUEST ITEMS TABLE (Guest Uploads)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.file_request_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES public.file_requests(id) ON DELETE CASCADE,
    storage_path TEXT NOT NULL UNIQUE,
    size_bytes BIGINT NOT NULL,
    guest_public_key_spki TEXT NOT NULL,
    wrapped_key_bundle JSONB NOT NULL,
    encrypted_meta JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending_upload', 'ready', 'deleted')) DEFAULT 'pending_upload',
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_file_request_items_req ON public.file_request_items (request_id);
CREATE INDEX IF NOT EXISTS idx_file_request_items_status ON public.file_request_items (status);

ALTER TABLE public.file_request_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.file_request_items FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.file_request_items FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.file_request_items TO service_role;

-- ----------------------------------------------------------------------------
-- 5. STORAGE DELETION QUEUE (Deferred Idempotent Cleanup)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.storage_deletion_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    storage_path TEXT NOT NULL UNIQUE,
    delete_after TIMESTAMPTZ NOT NULL DEFAULT (clock_timestamp() + INTERVAL '10 minutes'),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NULL,
    claimed_at TIMESTAMPTZ NULL,
    claim_expires_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_storage_deletion_queue_delete_after
    ON public.storage_deletion_queue (delete_after);
CREATE INDEX IF NOT EXISTS idx_storage_deletion_queue_claims
    ON public.storage_deletion_queue (claim_expires_at, attempts);

ALTER TABLE public.storage_deletion_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.storage_deletion_queue FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.storage_deletion_queue FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.storage_deletion_queue TO service_role;

-- ----------------------------------------------------------------------------
-- RPC: generate_download_challenge
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.generate_download_challenge(
    p_transfer_token TEXT,
    p_client_ip TEXT
)
RETURNS TABLE (
    res_success BOOLEAN,
    res_reason TEXT,
    res_challenge_id UUID,
    res_challenge_nonce TEXT,
    res_file_id UUID,
    res_pop_public_key_spki TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_file public.file_transfers%ROWTYPE;
    v_active_ip_challenges INTEGER;
    v_total_pending INTEGER;
    v_nonce BYTEA;
    v_new_challenge_id UUID;
BEGIN
    -- 1. Fetch file record
    SELECT * INTO v_file
    FROM public.file_transfers
    WHERE transfer_token = p_transfer_token;

    IF NOT FOUND OR v_file.id IS NULL THEN
        RETURN QUERY SELECT false, 'file_not_found'::TEXT, NULL::UUID, NULL::TEXT, NULL::UUID, NULL::TEXT;
        RETURN;
    END IF;

    IF v_file.download_count >= v_file.max_downloads OR v_file.status = 'completed' THEN
        RETURN QUERY SELECT false, 'max_downloads_reached'::TEXT, NULL::UUID, NULL::TEXT, NULL::UUID, NULL::TEXT;
        RETURN;
    END IF;

    IF v_file.expires_at <= clock_timestamp() THEN
        RETURN QUERY SELECT false, 'file_expired'::TEXT, NULL::UUID, NULL::TEXT, NULL::UUID, NULL::TEXT;
        RETURN;
    END IF;

    IF v_file.status != 'ready' THEN
        RETURN QUERY SELECT false, 'file_not_ready'::TEXT, NULL::UUID, NULL::TEXT, NULL::UUID, NULL::TEXT;
        RETURN;
    END IF;

    -- 2. Concurrency checks
    -- Check client IP has at most 1 active pending challenge
    SELECT COUNT(*) INTO v_active_ip_challenges
    FROM public.download_challenges
    WHERE file_id = v_file.id
      AND client_ip = p_client_ip
      AND status = 'pending'
      AND expires_at > clock_timestamp();

    IF v_active_ip_challenges >= 2 THEN
        RETURN QUERY SELECT false, 'too_many_pending_ip_challenges'::TEXT, NULL::UUID, NULL::TEXT, NULL::UUID, NULL::TEXT;
        RETURN;
    END IF;

    -- Check total pending challenges for this file
    SELECT COUNT(*) INTO v_total_pending
    FROM public.download_challenges
    WHERE file_id = v_file.id
      AND status = 'pending'
      AND expires_at > clock_timestamp();

    IF v_total_pending >= 10 THEN
        RETURN QUERY SELECT false, 'too_many_concurrent_challenges'::TEXT, NULL::UUID, NULL::TEXT, NULL::UUID, NULL::TEXT;
        RETURN;
    END IF;

    -- 3. Generate 16 bytes CSPRNG nonce
    v_nonce := gen_random_bytes(16);
    v_new_challenge_id := gen_random_uuid();

    INSERT INTO public.download_challenges (
        id,
        file_id,
        client_ip,
        challenge_nonce,
        status,
        expires_at
    ) VALUES (
        v_new_challenge_id,
        v_file.id,
        p_client_ip,
        v_nonce,
        'pending',
        clock_timestamp() + INTERVAL '60 seconds'
    );

    RETURN QUERY SELECT
        true,
        'challenge_created'::TEXT,
        v_new_challenge_id,
        encode(v_nonce, 'hex'),
        v_file.id,
        v_file.pop_public_key_spki;
END;
$$;

REVOKE ALL ON FUNCTION public.generate_download_challenge(TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.generate_download_challenge(TEXT, TEXT) TO service_role;

-- ----------------------------------------------------------------------------
-- RPC: consume_file_download
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.consume_file_download(
    p_file_id UUID,
    p_challenge_id UUID,
    p_grace_period_minutes INTEGER DEFAULT 10
)
RETURNS TABLE (
    res_success BOOLEAN,
    res_reason TEXT,
    res_storage_path TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_file RECORD;
    v_chal RECORD;
    v_grace INTERVAL;
BEGIN
    v_grace := GREATEST(5, LEAST(COALESCE(p_grace_period_minutes, 10), 60)) * INTERVAL '1 minute';

    -- 1. Exclusive row lock on file
    SELECT id, status, download_count, max_downloads, storage_path, expires_at
    INTO v_file
    FROM public.file_transfers
    WHERE id = p_file_id
    FOR UPDATE;

    IF NOT FOUND OR v_file.id IS NULL THEN
        RETURN QUERY SELECT false, 'file_not_found'::TEXT, NULL::TEXT;
        RETURN;
    END IF;

    IF v_file.status != 'ready' THEN
        RETURN QUERY SELECT false, 'invalid_file_status'::TEXT, NULL::TEXT;
        RETURN;
    END IF;

    IF v_file.expires_at <= clock_timestamp() THEN
        RETURN QUERY SELECT false, 'file_expired'::TEXT, NULL::TEXT;
        RETURN;
    END IF;

    IF v_file.download_count >= v_file.max_downloads THEN
        RETURN QUERY SELECT false, 'max_downloads_reached'::TEXT, NULL::TEXT;
        RETURN;
    END IF;

    -- 2. Exclusive row lock on challenge
    SELECT id, status, expires_at
    INTO v_chal
    FROM public.download_challenges
    WHERE id = p_challenge_id AND file_id = p_file_id
    FOR UPDATE;

    IF NOT FOUND OR v_chal.id IS NULL THEN
        RETURN QUERY SELECT false, 'challenge_not_found'::TEXT, NULL::TEXT;
        RETURN;
    END IF;

    IF v_chal.status != 'pending' THEN
        RETURN QUERY SELECT false, 'challenge_already_used_or_invalid'::TEXT, NULL::TEXT;
        RETURN;
    END IF;

    IF v_chal.expires_at <= clock_timestamp() THEN
        UPDATE public.download_challenges
        SET status = 'expired'
        WHERE id = p_challenge_id;

        RETURN QUERY SELECT false, 'challenge_expired'::TEXT, NULL::TEXT;
        RETURN;
    END IF;

    -- 3. Atomic consumption & download count increment
    UPDATE public.download_challenges
    SET status = 'consumed',
        consumed_at = clock_timestamp()
    WHERE id = p_challenge_id;

    UPDATE public.file_transfers
    SET download_count = download_count + 1,
        used_at = CASE WHEN download_count + 1 >= max_downloads THEN clock_timestamp() ELSE used_at END,
        status = CASE WHEN download_count + 1 >= max_downloads THEN 'completed' ELSE 'ready' END
    WHERE id = p_file_id;

    -- 4. Idempotent queue insertion for deferred storage deletion if completed
    IF v_file.download_count + 1 >= v_file.max_downloads THEN
        INSERT INTO public.storage_deletion_queue (storage_path, delete_after)
        VALUES (v_file.storage_path, clock_timestamp() + v_grace)
        ON CONFLICT (storage_path) DO UPDATE
        SET delete_after = LEAST(storage_deletion_queue.delete_after, EXCLUDED.delete_after);
    END IF;

    RETURN QUERY SELECT true, 'authorized'::TEXT, v_file.storage_path;
END;
$$;

REVOKE ALL ON FUNCTION public.consume_file_download(UUID, UUID, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_file_download(UUID, UUID, INTEGER) TO service_role;

-- ----------------------------------------------------------------------------
-- RPC: reserve_request_item
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.reserve_request_item(
    p_request_token TEXT,
    p_storage_path TEXT,
    p_size_bytes BIGINT
)
RETURNS TABLE (
    res_success BOOLEAN,
    res_reason TEXT,
    res_item_id UUID,
    res_request_id UUID
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_req RECORD;
    v_new_item_id UUID;
BEGIN
    SELECT id, status, files_count, max_files, max_bytes_per_file, expires_at
    INTO v_req
    FROM public.file_requests
    WHERE request_token = p_request_token
    FOR UPDATE;

    IF NOT FOUND OR v_req.id IS NULL THEN
        RETURN QUERY SELECT false, 'request_not_found'::TEXT, NULL::UUID, NULL::UUID;
        RETURN;
    END IF;

    IF v_req.status != 'active' THEN
        RETURN QUERY SELECT false, 'request_not_active'::TEXT, NULL::UUID, NULL::UUID;
        RETURN;
    END IF;

    IF v_req.expires_at <= clock_timestamp() THEN
        RETURN QUERY SELECT false, 'request_expired'::TEXT, NULL::UUID, NULL::UUID;
        RETURN;
    END IF;

    IF v_req.files_count >= v_req.max_files THEN
        RETURN QUERY SELECT false, 'request_max_files_reached'::TEXT, NULL::UUID, NULL::UUID;
        RETURN;
    END IF;

    IF p_size_bytes > v_req.max_bytes_per_file THEN
        RETURN QUERY SELECT false, 'file_too_large'::TEXT, NULL::UUID, NULL::UUID;
        RETURN;
    END IF;

    v_new_item_id := gen_random_uuid();

    INSERT INTO public.file_request_items (
        id,
        request_id,
        storage_path,
        size_bytes,
        guest_public_key_spki,
        wrapped_key_bundle,
        encrypted_meta,
        status
    ) VALUES (
        v_new_item_id,
        v_req.id,
        p_storage_path,
        p_size_bytes,
        '',
        '{}'::jsonb,
        '{}'::jsonb,
        'pending_upload'
    );

    RETURN QUERY SELECT true, 'slot_reserved'::TEXT, v_new_item_id, v_req.id;
END;
$$;

REVOKE ALL ON FUNCTION public.reserve_request_item(TEXT, TEXT, BIGINT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.reserve_request_item(TEXT, TEXT, BIGINT) TO service_role;

-- ----------------------------------------------------------------------------
-- RPC: confirm_request_item
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.confirm_request_item(
    p_item_id UUID,
    p_guest_public_key_spki TEXT,
    p_wrapped_key_bundle JSONB,
    p_encrypted_meta JSONB
)
RETURNS TABLE (
    res_success BOOLEAN,
    res_reason TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_item RECORD;
    v_req RECORD;
BEGIN
    SELECT id, request_id, status
    INTO v_item
    FROM public.file_request_items
    WHERE id = p_item_id
    FOR UPDATE;

    IF NOT FOUND OR v_item.id IS NULL THEN
        RETURN QUERY SELECT false, 'item_not_found'::TEXT;
        RETURN;
    END IF;

    IF v_item.status != 'pending_upload' THEN
        RETURN QUERY SELECT false, 'invalid_item_status'::TEXT;
        RETURN;
    END IF;

    SELECT id, status, files_count, max_files
    INTO v_req
    FROM public.file_requests
    WHERE id = v_item.request_id
    FOR UPDATE;

    IF NOT FOUND OR v_req.id IS NULL THEN
        RETURN QUERY SELECT false, 'request_not_found'::TEXT;
        RETURN;
    END IF;

    -- Update item to ready
    UPDATE public.file_request_items
    SET status = 'ready',
        guest_public_key_spki = p_guest_public_key_spki,
        wrapped_key_bundle = p_wrapped_key_bundle,
        encrypted_meta = p_encrypted_meta
    WHERE id = p_item_id;

    -- Increment request files count
    UPDATE public.file_requests
    SET files_count = files_count + 1
    WHERE id = v_req.id;

    RETURN QUERY SELECT true, 'item_confirmed'::TEXT;
END;
$$;

REVOKE ALL ON FUNCTION public.confirm_request_item(UUID, TEXT, JSONB, JSONB) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.confirm_request_item(UUID, TEXT, JSONB, JSONB) TO service_role;

-- ----------------------------------------------------------------------------
-- RPC: close_file_request
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.close_file_request(
    p_owner_token_hash TEXT
)
RETURNS TABLE (
    res_success BOOLEAN,
    res_reason TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_req RECORD;
    v_item RECORD;
BEGIN
    SELECT id, status
    INTO v_req
    FROM public.file_requests
    WHERE owner_token_hash = p_owner_token_hash
    FOR UPDATE;

    IF NOT FOUND OR v_req.id IS NULL THEN
        RETURN QUERY SELECT false, 'request_not_found'::TEXT;
        RETURN;
    END IF;

    IF v_req.status = 'closed' THEN
        RETURN QUERY SELECT true, 'already_closed'::TEXT;
        RETURN;
    END IF;

    -- Close the request
    UPDATE public.file_requests
    SET status = 'closed',
        closed_at = clock_timestamp()
    WHERE id = v_req.id;

    -- Queue all uploaded items for deletion
    FOR v_item IN
        SELECT storage_path FROM public.file_request_items
        WHERE request_id = v_req.id AND status != 'deleted'
    LOOP
        INSERT INTO public.storage_deletion_queue (storage_path, delete_after)
        VALUES (v_item.storage_path, clock_timestamp() + INTERVAL '10 minutes')
        ON CONFLICT (storage_path) DO NOTHING;
    END LOOP;

    UPDATE public.file_request_items
    SET status = 'deleted'
    WHERE request_id = v_req.id;

    RETURN QUERY SELECT true, 'request_closed'::TEXT;
END;
$$;

REVOKE ALL ON FUNCTION public.close_file_request(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.close_file_request(TEXT) TO service_role;

-- ----------------------------------------------------------------------------
-- RPC: delete_request_item
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.delete_request_item(
    p_owner_token_hash TEXT,
    p_item_id UUID
)
RETURNS TABLE (
    res_success BOOLEAN,
    res_reason TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_req RECORD;
    v_item RECORD;
BEGIN
    SELECT id
    INTO v_req
    FROM public.file_requests
    WHERE owner_token_hash = p_owner_token_hash;

    IF NOT FOUND OR v_req.id IS NULL THEN
        RETURN QUERY SELECT false, 'request_not_found'::TEXT;
        RETURN;
    END IF;

    SELECT id, storage_path, status
    INTO v_item
    FROM public.file_request_items
    WHERE id = p_item_id AND request_id = v_req.id
    FOR UPDATE;

    IF NOT FOUND OR v_item.id IS NULL THEN
        RETURN QUERY SELECT false, 'item_not_found'::TEXT;
        RETURN;
    END IF;

    UPDATE public.file_request_items
    SET status = 'deleted'
    WHERE id = p_item_id;

    INSERT INTO public.storage_deletion_queue (storage_path, delete_after)
    VALUES (v_item.storage_path, clock_timestamp() + INTERVAL '10 minutes')
    ON CONFLICT (storage_path) DO NOTHING;

    RETURN QUERY SELECT true, 'item_deleted'::TEXT;
END;
$$;

REVOKE ALL ON FUNCTION public.delete_request_item(TEXT, UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.delete_request_item(TEXT, UUID) TO service_role;

-- ----------------------------------------------------------------------------
-- RPC: confirm_transfer_upload (Two-Phase Upload Confirmation)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.confirm_transfer_upload(
    p_transfer_token TEXT
)
RETURNS TABLE (
    res_success BOOLEAN,
    res_reason TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_file RECORD;
BEGIN
    SELECT id, status, expires_at
    INTO v_file
    FROM public.file_transfers
    WHERE transfer_token = p_transfer_token
    FOR UPDATE;

    IF NOT FOUND OR v_file.id IS NULL THEN
        RETURN QUERY SELECT false, 'file_not_found'::TEXT;
        RETURN;
    END IF;

    IF v_file.status = 'ready' THEN
        RETURN QUERY SELECT true, 'already_confirmed'::TEXT;
        RETURN;
    END IF;

    IF v_file.status != 'pending_upload' THEN
        RETURN QUERY SELECT false, 'invalid_file_status'::TEXT;
        RETURN;
    END IF;

    IF v_file.expires_at <= clock_timestamp() THEN
        RETURN QUERY SELECT false, 'file_expired'::TEXT;
        RETURN;
    END IF;

    UPDATE public.file_transfers
    SET status = 'ready'
    WHERE id = v_file.id;

    RETURN QUERY SELECT true, 'confirmed'::TEXT;
END;
$$;

REVOKE ALL ON FUNCTION public.confirm_transfer_upload(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.confirm_transfer_upload(TEXT) TO service_role;

-- ----------------------------------------------------------------------------
-- RPC: claim_deletion_queue_batch (Lease-Based Job Claiming)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.claim_deletion_queue_batch(
    p_batch_size INTEGER DEFAULT 50,
    p_lease_seconds INTEGER DEFAULT 60
)
RETURNS TABLE (
    res_id UUID,
    res_storage_path TEXT,
    res_attempts INTEGER
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    WITH candidate_items AS (
        SELECT q.id
        FROM public.storage_deletion_queue q
        WHERE q.delete_after <= clock_timestamp()
          AND (q.claim_expires_at IS NULL OR q.claim_expires_at < clock_timestamp())
          AND q.attempts < 10
        ORDER BY q.delete_after ASC
        LIMIT p_batch_size
        FOR UPDATE SKIP LOCKED
    )
    UPDATE public.storage_deletion_queue target
    SET claimed_at = clock_timestamp(),
        claim_expires_at = clock_timestamp() + make_interval(secs => p_lease_seconds)
    FROM candidate_items
    WHERE target.id = candidate_items.id
    RETURNING target.id, target.storage_path, target.attempts;
END;
$$;

REVOKE ALL ON FUNCTION public.claim_deletion_queue_batch(INTEGER, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.claim_deletion_queue_batch(INTEGER, INTEGER) TO service_role;

-- ----------------------------------------------------------------------------
-- RPC: finalize_deletion_queue_success
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.finalize_deletion_queue_success(
    p_ids UUID[]
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    DELETE FROM public.storage_deletion_queue
    WHERE id = ANY(p_ids);
END;
$$;

REVOKE ALL ON FUNCTION public.finalize_deletion_queue_success(UUID[]) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.finalize_deletion_queue_success(UUID[]) TO service_role;

-- ----------------------------------------------------------------------------
-- RPC: record_deletion_queue_failure
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.record_deletion_queue_failure(
    p_id UUID,
    p_error TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    UPDATE public.storage_deletion_queue
    SET attempts = attempts + 1,
        last_error = p_error,
        claim_expires_at = NULL,
        delete_after = clock_timestamp() + (power(2, LEAST(attempts + 1, 8)) * INTERVAL '1 minute')
    WHERE id = p_id;
END;
$$;

REVOKE ALL ON FUNCTION public.record_deletion_queue_failure(UUID, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_deletion_queue_failure(UUID, TEXT) TO service_role;

-- ----------------------------------------------------------------------------
-- RPC: cleanup_expired_files_cron
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.cleanup_expired_files_cron()
RETURNS TABLE (
    expired_transfers_count INTEGER,
    expired_requests_count INTEGER,
    expired_pending_items_count INTEGER,
    queued_for_deletion_count INTEGER
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_transfers INTEGER := 0;
    v_requests INTEGER := 0;
    v_pending_items INTEGER := 0;
    v_rec RECORD;
BEGIN
    -- 1. Expire transfers
    FOR v_rec IN
        SELECT id, storage_path FROM public.file_transfers
        WHERE status IN ('pending_upload', 'ready')
          AND expires_at <= clock_timestamp()
        FOR UPDATE
    LOOP
        UPDATE public.file_transfers SET status = 'expired' WHERE id = v_rec.id;
        INSERT INTO public.storage_deletion_queue (storage_path, delete_after)
        VALUES (v_rec.storage_path, clock_timestamp())
        ON CONFLICT (storage_path) DO UPDATE
        SET delete_after = LEAST(storage_deletion_queue.delete_after, EXCLUDED.delete_after);
        v_transfers := v_transfers + 1;
    END LOOP;

    -- 2. Expire requests and queue items
    FOR v_rec IN
        SELECT id FROM public.file_requests
        WHERE status = 'active'
          AND expires_at <= clock_timestamp()
        FOR UPDATE
    LOOP
        UPDATE public.file_requests SET status = 'expired' WHERE id = v_rec.id;
        v_requests := v_requests + 1;

        INSERT INTO public.storage_deletion_queue (storage_path, delete_after)
        SELECT storage_path, clock_timestamp()
        FROM public.file_request_items
        WHERE request_id = v_rec.id AND status != 'deleted'
        ON CONFLICT (storage_path) DO NOTHING;

        UPDATE public.file_request_items SET status = 'deleted' WHERE request_id = v_rec.id;
    END LOOP;

    -- 3. Recover orphan request items in pending_upload older than 2 hours
    FOR v_rec IN
        SELECT id, storage_path
        FROM public.file_request_items
        WHERE status = 'pending_upload'
          AND created_at <= clock_timestamp() - INTERVAL '2 hours'
        FOR UPDATE
    LOOP
        UPDATE public.file_request_items SET status = 'deleted' WHERE id = v_rec.id;
        INSERT INTO public.storage_deletion_queue (storage_path, delete_after)
        VALUES (v_rec.storage_path, clock_timestamp())
        ON CONFLICT (storage_path) DO NOTHING;
        v_pending_items := v_pending_items + 1;
    END LOOP;

    -- 4. Mark old challenges expired
    UPDATE public.download_challenges
    SET status = 'expired'
    WHERE status = 'pending' AND expires_at <= clock_timestamp();

    RETURN QUERY SELECT
        v_transfers,
        v_requests,
        v_pending_items,
        (SELECT COUNT(*)::INTEGER FROM public.storage_deletion_queue WHERE delete_after <= clock_timestamp() AND attempts < 10);
END;
$$;

REVOKE ALL ON FUNCTION public.cleanup_expired_files_cron() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.cleanup_expired_files_cron() TO service_role;
