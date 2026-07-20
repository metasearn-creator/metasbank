-- ============================================================
-- Security Fixes — Run in Supabase Dashboard SQL Editor
-- ============================================================
-- Fixes:
--   1. RLS: restrict member tables to own rows (auth.uid)
--   2. Login RPC (returns auth_password only for matching creds)
--   3. Auth checks on write RPCs
--   4. Protect confirm_auth_user
-- ============================================================

-- ============================================================
-- 1. RLS: Replace wide-open SELECT policies with row-level auth
-- ============================================================

-- Members: only see your own record
DROP POLICY IF EXISTS "anon_select_members" ON members;
CREATE POLICY "member_select_self" ON members FOR SELECT
  USING (auth.uid() = auth_uid);

-- Accounts: only see accounts linked to your member record
DROP POLICY IF EXISTS "anon_select_accounts" ON accounts;
CREATE POLICY "member_select_own_accounts" ON accounts FOR SELECT
  USING (member_id IN (SELECT id FROM members WHERE auth_uid = auth.uid()));

-- Transactions: only your own
DROP POLICY IF EXISTS "anon_select_transactions" ON transactions;
CREATE POLICY "member_select_own_transactions" ON transactions FOR SELECT
  USING (member_id IN (SELECT id FROM members WHERE auth_uid = auth.uid()));

-- Deposits: only your own
DROP POLICY IF EXISTS "anon_select_deposits" ON deposits;
CREATE POLICY "member_select_own_deposits" ON deposits FOR SELECT
  USING (member_id IN (SELECT id FROM members WHERE auth_uid = auth.uid()));

-- Withdrawals: only your own
DROP POLICY IF EXISTS "anon_select_withdrawals" ON withdrawals;
CREATE POLICY "member_select_own_withdrawals" ON withdrawals FOR SELECT
  USING (member_id IN (SELECT id FROM members WHERE auth_uid = auth.uid()));

-- Notifications: only your own
DROP POLICY IF EXISTS "anon_select_notifications" ON notifications;
CREATE POLICY "member_select_own_notifications" ON notifications FOR SELECT
  USING (member_id IN (SELECT id FROM members WHERE auth_uid = auth.uid()));

-- Chat conversations: only your own
DROP POLICY IF EXISTS "anon_select_chat_conversations" ON chat_conversations;
CREATE POLICY "member_select_own_conversations" ON chat_conversations FOR SELECT
  USING (member_id IN (SELECT id FROM members WHERE auth_uid = auth.uid()));

-- Chat messages: only messages in your conversations
DROP POLICY IF EXISTS "anon_select_chat_messages" ON chat_messages;
CREATE POLICY "member_select_own_messages" ON chat_messages FOR SELECT
  USING (conversation_id IN (
    SELECT id FROM chat_conversations
    WHERE member_id IN (SELECT id FROM members WHERE auth_uid = auth.uid())
  ));

-- Chat ratings: only your own
DROP POLICY IF EXISTS "anon_select_chat_ratings" ON chat_ratings;
CREATE POLICY "member_select_own_ratings" ON chat_ratings FOR SELECT
  USING (conversation_id IN (
    SELECT id FROM chat_conversations
    WHERE member_id IN (SELECT id FROM members WHERE auth_uid = auth.uid())
  ));

-- Account requests: only your own
DROP POLICY IF EXISTS "anon_select_account_requests" ON account_requests;
CREATE POLICY "member_select_own_requests" ON account_requests FOR SELECT
  USING (member_id IN (SELECT id FROM members WHERE auth_uid = auth.uid()));

-- ============================================================
-- 2. Secure Login RPC (bypasses RLS, returns auth_password)
--    only for the matching member
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_member_login(p_identifier TEXT, p_access_key TEXT)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_member members%ROWTYPE;
  v_result JSONB;
BEGIN
  -- Look up member by access_key + email/username
  SELECT * INTO v_member FROM members
  WHERE access_key = p_access_key
    AND (email = p_identifier OR username = p_identifier)
    AND status = 'active';

  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'Invalid credentials');
  END IF;

  -- Return member data including auth_password (needed by client
  -- to complete Supabase Auth sign-in). auth_password is never
  -- exposed via the RLS-protected SELECT — only through this RPC.
  v_result := jsonb_build_object(
    'id', v_member.id,
    'name', v_member.name,
    'username', v_member.username,
    'email', v_member.email,
    'balance', v_member.balance,
    'status', v_member.status,
    'access_key', v_member.access_key,
    'auth_uid', v_member.auth_uid,
    'auth_password', v_member.auth_password,
    'created_at', v_member.created_at,
    'last_login', v_member.last_login
  );

  UPDATE members SET last_login = NOW() WHERE id = v_member.id;

  RETURN v_result;
END;
$$;

-- ============================================================
-- 3. Auth checks on write RPCs
--    Verify auth.uid() matches the member being written
-- ============================================================

-- Member update
CREATE OR REPLACE FUNCTION rpc_update_member(
  p_id UUID,
  p_email TEXT DEFAULT NULL,
  p_name TEXT DEFAULT NULL,
  p_access_key TEXT DEFAULT NULL,
  p_status TEXT DEFAULT NULL,
  p_balance NUMERIC DEFAULT NULL,
  p_last_login TIMESTAMPTZ DEFAULT NULL,
  p_auth_uid UUID DEFAULT NULL,
  p_auth_password TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
  v_auth_uid UUID;
BEGIN
  -- Get the member's current auth_uid
  SELECT auth_uid INTO v_auth_uid FROM members WHERE id = p_id;

  -- Allow if: caller owns the record OR the record has no auth_uid yet (signup)
  IF v_auth_uid IS NOT NULL AND auth.uid() IS DISTINCT FROM v_auth_uid THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;

  UPDATE members SET
    email = COALESCE(p_email, email),
    name = COALESCE(p_name, name),
    access_key = COALESCE(p_access_key, access_key),
    status = COALESCE(p_status, status),
    balance = COALESCE(p_balance, balance),
    last_login = COALESCE(p_last_login, last_login),
    auth_uid = COALESCE(p_auth_uid, auth_uid),
    auth_password = COALESCE(p_auth_password, auth_password)
  WHERE id = p_id;

  IF FOUND THEN
    v_result := jsonb_build_object('success', true);
  ELSE
    v_result := jsonb_build_object('success', false, 'error', 'Member not found');
  END IF;
  RETURN v_result;
END;
$$;

-- Insert transaction (member-facing)
CREATE OR REPLACE FUNCTION rpc_insert_transaction(
  p_member_id UUID, p_type TEXT, p_method TEXT, p_amount NUMERIC,
  p_status TEXT, p_reference TEXT DEFAULT NULL,
  p_balance_before NUMERIC DEFAULT NULL, p_balance_after NUMERIC DEFAULT NULL,
  p_fee_amount NUMERIC DEFAULT NULL, p_sender_name TEXT DEFAULT NULL,
  p_payout_info JSONB DEFAULT NULL, p_transaction_no TEXT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM members WHERE id = p_member_id AND auth_uid = auth.uid()) THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  INSERT INTO transactions (member_id, type, method, amount, status, reference, balance_before, balance_after, fee_amount, sender_name, payout_info, transaction_no, created_at)
  VALUES (p_member_id, p_type, p_method, p_amount, p_status, p_reference, p_balance_before, p_balance_after, p_fee_amount, p_sender_name, p_payout_info, p_transaction_no, NOW())
  RETURNING row_to_json(transactions)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

-- Insert deposit
CREATE OR REPLACE FUNCTION rpc_insert_deposit(
  p_member_id UUID, p_method TEXT, p_amount NUMERIC, p_status TEXT,
  p_reference TEXT, p_note TEXT DEFAULT NULL, p_coin TEXT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM members WHERE id = p_member_id AND auth_uid = auth.uid()) THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  INSERT INTO deposits (member_id, method, amount, status, reference, note, coin, created_at)
  VALUES (p_member_id, p_method, p_amount, p_status, p_reference, p_note, p_coin, NOW())
  RETURNING row_to_json(deposits)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

-- Insert withdrawal
CREATE OR REPLACE FUNCTION rpc_insert_withdrawal(
  p_member_id UUID, p_method TEXT, p_amount NUMERIC,
  p_status TEXT, p_reference TEXT,
  p_payout_info JSONB DEFAULT NULL,
  p_fee_amount NUMERIC DEFAULT NULL,
  p_coin TEXT DEFAULT NULL,
  p_destination_type TEXT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
  v_is_auth BOOLEAN;
BEGIN
  SELECT EXISTS (SELECT 1 FROM members WHERE id = p_member_id AND auth_uid = auth.uid()) INTO v_is_auth;
  IF NOT v_is_auth THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  INSERT INTO withdrawals (member_id, method, amount, status, reference, payout_info, fee_amount, coin, destination_type, created_at)
  VALUES (p_member_id, p_method, p_amount, p_status, p_reference, p_payout_info, p_fee_amount, p_coin, p_destination_type, NOW())
  RETURNING row_to_json(withdrawals)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

-- Insert notification
CREATE OR REPLACE FUNCTION rpc_insert_notification(
  p_member_id UUID, p_title TEXT, p_message TEXT,
  p_type TEXT DEFAULT 'info'
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM members WHERE id = p_member_id AND auth_uid = auth.uid()) THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  INSERT INTO notifications (member_id, title, message, type, created_at)
  VALUES (p_member_id, p_title, p_message, p_type, NOW())
  RETURNING row_to_json(notifications)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

-- Insert account request
CREATE OR REPLACE FUNCTION rpc_insert_account_request(
  p_member_id UUID,
  p_account_type TEXT DEFAULT 'checking',
  p_first_name TEXT DEFAULT NULL,
  p_middle_name TEXT DEFAULT NULL,
  p_last_name TEXT DEFAULT NULL,
  p_tax_id TEXT DEFAULT NULL,
  p_date_of_birth TEXT DEFAULT NULL,
  p_address_street TEXT DEFAULT NULL,
  p_address_city TEXT DEFAULT NULL,
  p_address_state TEXT DEFAULT NULL,
  p_address_zip TEXT DEFAULT NULL,
  p_phone TEXT DEFAULT NULL,
  p_id_type TEXT DEFAULT NULL,
  p_id_number TEXT DEFAULT NULL,
  p_status TEXT DEFAULT 'pending'
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM members WHERE id = p_member_id AND auth_uid = auth.uid()) THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  INSERT INTO account_requests (member_id, account_type, first_name, middle_name, last_name, tax_id, date_of_birth, address_street, address_city, address_state, address_zip, phone, id_type, id_number, status, created_at)
  VALUES (p_member_id, p_account_type, p_first_name, p_middle_name, p_last_name, p_tax_id, p_date_of_birth, p_address_street, p_address_city, p_address_state, p_address_zip, p_phone, p_id_type, p_id_number, p_status, NOW())
  RETURNING row_to_json(account_requests)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

-- Insert chat message
CREATE OR REPLACE FUNCTION rpc_insert_chat_message(
  p_conversation_id UUID, p_sender TEXT, p_message TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
  v_member_id UUID;
BEGIN
  SELECT member_id INTO v_member_id FROM chat_conversations WHERE id = p_conversation_id;
  IF v_member_id IS NULL THEN
    RAISE EXCEPTION 'Conversation not found';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM members WHERE id = v_member_id AND auth_uid = auth.uid()) THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  INSERT INTO chat_messages (conversation_id, sender, message, created_at)
  VALUES (p_conversation_id, p_sender, p_message, NOW())
  RETURNING row_to_json(chat_messages)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

-- Insert chat conversation
CREATE OR REPLACE FUNCTION rpc_insert_chat_conversation(
  p_member_id UUID, p_subject TEXT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM members WHERE id = p_member_id AND auth_uid = auth.uid()) THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  INSERT INTO chat_conversations (member_id, subject, created_at)
  VALUES (p_member_id, p_subject, NOW())
  RETURNING row_to_json(chat_conversations)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

-- ============================================================
-- 4. Protect confirm_auth_user — only allow confirming yourself
-- ============================================================

CREATE OR REPLACE FUNCTION confirm_auth_user(user_id uuid)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  IF auth.uid() IS DISTINCT FROM user_id THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  UPDATE auth.users
  SET email_confirmed_at = COALESCE(email_confirmed_at, now())
  WHERE id = user_id;
  RETURN FOUND;
END;
$$;
