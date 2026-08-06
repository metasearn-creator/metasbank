-- ============================================================================
-- MetasBank: Delete path for pre_deposits (deposit links)
-- Run this in the Supabase Dashboard → SQL Editor (against project
-- pkhftlbacapcarwnrhzn).
--
-- The admin Deposit Links table now has a Delete button that calls
-- rpc_admin_delete_pre_deposit. RLS would otherwise block direct deletes,
-- so this SECURITY DEFINER function is the only way the anon/authenticated
-- keys can remove a stale or erroneous deposit link.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.rpc_admin_delete_pre_deposit(p_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  DELETE FROM public.pre_deposits WHERE id = p_id;
  RETURN FOUND;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.rpc_admin_delete_pre_deposit(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rpc_admin_delete_pre_deposit(uuid) TO anon, authenticated;
