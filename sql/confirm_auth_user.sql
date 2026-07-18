-- Run this SQL in your Supabase Dashboard SQL Editor (https://supabase.com/dashboard/project/YOUR_PROJECT_ID/sql)
-- This function auto-confirms a user's email after signup, bypassing the confirmation email

CREATE OR REPLACE FUNCTION confirm_auth_user(user_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE auth.users
  SET email_confirmed_at = COALESCE(email_confirmed_at, now())
  WHERE id = user_id;
  RETURN FOUND;
END;
$$;
