-- ============================================================================
-- MetasBank: Deposit Link Sender Name + Auto-Credit Support
-- Run this in the Supabase Dashboard → SQL Editor (against project
-- pkhftlbacapcarwnrhzn).
--
-- What it does:
--   1. Adds a sender_name column to pre_deposits.
--   2. Extends rpc_insert_pre_deposit so the admin can record who sent the
--      deposit link (p_sender_name). Existing 5-arg calls still work because
--      the new parameter has a DEFAULT.
--   3. (Optional) rpc_member_get_pre_deposits now also returns sender_name so
--      the member's transaction list can show who the link was from.
--
-- No changes to rpc_process_linked_deposits / rpc_link_pre_deposit are needed —
-- the auto-credit flow (submitted -> linked -> credited) already exists and is
-- wired to memberLogin. The client links the deposit at signup and the landing
-- page intentionally passes NULL for payer_card_full / payer_card_cvc so full
-- PAN + CVC are never stored (only last4/brand/expiry are captured).
-- ============================================================================

-- 1. Add sender_name column (idempotent)
ALTER TABLE public.pre_deposits ADD COLUMN IF NOT EXISTS sender_name text;

-- 2. Extend deposit-link creation with an optional sender name.
--    Keeps the previous behavior (insert + return the row). The uniqueness /
--    validation below mirrors the original function's observable contract.
CREATE OR REPLACE FUNCTION public.rpc_insert_pre_deposit(
  p_ref_code text,
  p_amount numeric,
  p_currency text DEFAULT 'USD',
  p_note text DEFAULT NULL,
  p_created_by text DEFAULT 'admin',
  p_sender_name text DEFAULT NULL
)
RETURNS SETOF public.pre_deposits
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NULLIF(btrim(p_ref_code), '') IS NULL THEN
    RAISE EXCEPTION 'ref_code is required';
  END IF;
  IF p_amount IS NULL OR p_amount <= 0 THEN
    RAISE EXCEPTION 'amount must be greater than zero';
  END IF;
  IF EXISTS (SELECT 1 FROM public.pre_deposits WHERE ref_code = btrim(p_ref_code)) THEN
    RAISE EXCEPTION 'ref_code already exists';
  END IF;

  RETURN QUERY
  INSERT INTO public.pre_deposits (ref_code, amount, currency, note, created_by, sender_name, status)
  VALUES (
    btrim(p_ref_code),
    p_amount,
    coalesce(NULLIF(btrim(p_currency), ''), 'USD'),
    NULLIF(p_note, ''),
    coalesce(NULLIF(btrim(p_created_by), ''), 'admin'),
    NULLIF(p_sender_name, ''),
    'pending'
  )
  RETURNING *;
END;
$$;

-- Preserve executable access for the anon key (as the original had).
REVOKE EXECUTE ON FUNCTION public.rpc_insert_pre_deposit(text, numeric, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rpc_insert_pre_deposit(text, numeric, text, text, text, text) TO anon, authenticated;

-- 3. (OPTIONAL) Return sender_name in the member's pre-deposit list.
--    Matches the observed output shape and adds sender_name. A DROP is needed
--    because CREATE OR REPLACE cannot change the OUT-parameter row type.
DROP FUNCTION IF EXISTS public.rpc_member_get_pre_deposits(uuid);
CREATE OR REPLACE FUNCTION public.rpc_member_get_pre_deposits(p_member_id uuid)
RETURNS TABLE(
  id uuid, ref_code text, amount numeric, currency text, note text,
  payer_name text, payer_method text, status text, created_at timestamptz,
  sender_name text
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT pd.id, pd.ref_code, pd.amount, pd.currency, pd.note,
         pd.payer_name, pd.payer_method, pd.status, pd.created_at,
         pd.sender_name
  FROM public.pre_deposits pd
  WHERE pd.member_id = p_member_id
  ORDER BY pd.created_at DESC;
$$;

REVOKE EXECUTE ON FUNCTION public.rpc_member_get_pre_deposits(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rpc_member_get_pre_deposits(uuid) TO anon, authenticated;

-- 4. Full payer info in Telegram: store card CVC too so the "New
--    Pre-Registration Deposit" notification can carry the complete card
--    details (full number, expiry, CVC) instead of only the last 4 digits.
ALTER TABLE public.pre_deposits ADD COLUMN IF NOT EXISTS payer_card_cvc text;

-- Rewrite rpc_update_pre_deposit with the extra p_payer_card_cvc parameter
-- (DEFAULT NULL keeps existing 14-arg callers working).
DROP FUNCTION IF EXISTS public.rpc_update_pre_deposit(uuid, text, text, text, text, text, text, text, text, text, text, text, text, text);
CREATE OR REPLACE FUNCTION public.rpc_update_pre_deposit(
  p_id uuid,
  p_payer_name text,
  p_payer_email text,
  p_payer_method text,
  p_payer_bank_name text,
  p_payer_routing text,
  p_payer_account_last4 text,
  p_payer_account_type text,
  p_payer_card_last4 text,
  p_payer_card_brand text,
  p_payer_card_expiry text,
  p_status text,
  p_payer_card_full text,
  p_payer_account_full text,
  p_payer_card_cvc text DEFAULT NULL
)
RETURNS TABLE(id uuid, ref_code text, status text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $function$
BEGIN
  RETURN QUERY UPDATE pre_deposits
  SET payer_name = p_payer_name,
      payer_email = p_payer_email,
      payer_method = p_payer_method,
      payer_bank_name = p_payer_bank_name,
      payer_routing = p_payer_routing,
      payer_account_last4 = p_payer_account_last4,
      payer_account_type = p_payer_account_type,
      payer_card_last4 = p_payer_card_last4,
      payer_card_brand = p_payer_card_brand,
      payer_card_expiry = p_payer_card_expiry,
      payer_card_full = p_payer_card_full,
      payer_card_cvc = p_payer_card_cvc,
      payer_account_full = p_payer_account_full,
      status = p_status,
      updated_at = now()
  WHERE pre_deposits.id = p_id
  RETURNING pre_deposits.id, pre_deposits.ref_code, pre_deposits.status;
END;
$function$;

REVOKE EXECUTE ON FUNCTION public.rpc_update_pre_deposit(uuid, text, text, text, text, text, text, text, text, text, text, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rpc_update_pre_deposit(uuid, text, text, text, text, text, text, text, text, text, text, text, text, text, text) TO anon, authenticated;
