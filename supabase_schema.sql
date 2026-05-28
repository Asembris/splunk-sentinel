-- Splunk Sentinel - Supabase Schema
-- Run this in your Supabase SQL Editor before
-- starting the backend for the first time.
--
-- How to run:
-- 1. Go to https://supabase.com/dashboard
-- 2. Open your project
-- 3. Click SQL Editor in the left sidebar
-- 4. Click New Query
-- 5. Paste this entire file
-- 6. Click Run
--
-- Verify after running:
-- SELECT COUNT(*) FROM public.investigations;
-- Expected: 0 rows (empty table, ready for use)

CREATE TABLE IF NOT EXISTS public.investigations (
    id                   UUID PRIMARY KEY
                         DEFAULT gen_random_uuid(),
    investigation_id     TEXT NOT NULL UNIQUE,
    created_at           TIMESTAMPTZ DEFAULT now(),
    classification       TEXT,
    severity             TEXT,
    confidence           DOUBLE PRECISION,
    trigger_text         TEXT,
    kill_chain_stages    INTEGER,
    patient_zero_ip      TEXT,
    containment_priority TEXT,
    report_json          JSONB,
    pdf_path             TEXT,
    splunk_notable_id    TEXT,
    analyst_feedback     TEXT,
    analyst_rating       TEXT,
    escalate_to_human    BOOLEAN
);

-- Enable Row Level Security
ALTER TABLE public.investigations
    ENABLE ROW LEVEL SECURITY;

-- Allow service role full access
-- (used by FastAPI backend via SUPABASE_SERVICE_KEY)
CREATE POLICY "Service role full access"
    ON public.investigations
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);
