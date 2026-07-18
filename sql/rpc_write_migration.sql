-- ============================================================
-- RPC Write Migration — All SECURITY DEFINER functions
-- Run this in Supabase Dashboard > SQL Editor
-- ============================================================
-- After this, anon key only needs SELECT on tables
-- All writes go through these RPCs with SECURITY DEFINER
-- ============================================================

-- ============================================================
-- MEMBERS
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_update_member(p_id UUID, p_email TEXT DEFAULT NULL, p_name TEXT DEFAULT NULL, p_access_key TEXT DEFAULT NULL, p_status TEXT DEFAULT NULL, p_balance NUMERIC DEFAULT NULL, p_last_login TIMESTAMPTZ DEFAULT NULL, p_auth_uid UUID DEFAULT NULL, p_auth_password TEXT DEFAULT NULL)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
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

CREATE OR REPLACE FUNCTION rpc_insert_member(
  p_email TEXT, p_name TEXT, p_username TEXT, p_access_key TEXT,
  p_balance NUMERIC DEFAULT 0, p_status TEXT DEFAULT 'active',
  p_auth_uid UUID DEFAULT NULL, p_auth_password TEXT DEFAULT NULL,
  p_ip_address TEXT DEFAULT NULL, p_date_of_birth TEXT DEFAULT NULL,
  p_phone TEXT DEFAULT NULL, p_address_street TEXT DEFAULT NULL,
  p_address_city TEXT DEFAULT NULL, p_address_state TEXT DEFAULT NULL,
  p_address_zip TEXT DEFAULT NULL, p_address_country TEXT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_member JSONB;
BEGIN
  INSERT INTO members (email, name, username, access_key, balance, status, auth_uid, auth_password, ip_address, date_of_birth, phone, address_street, address_city, address_state, address_zip, address_country, created_at)
  VALUES (p_email, p_name, p_username, p_access_key, p_balance, p_status, p_auth_uid, p_auth_password, p_ip_address, p_date_of_birth, p_phone, p_address_street, p_address_city, p_address_state, p_address_zip, p_address_country, NOW())
  RETURNING row_to_json(members)::JSONB INTO v_member;
  RETURN v_member;
END;
$$;

CREATE OR REPLACE FUNCTION rpc_deduct_member_balance(p_member_id UUID, p_amount NUMERIC, p_expected_balance NUMERIC)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_current NUMERIC;
  v_new NUMERIC;
BEGIN
  SELECT balance INTO v_current FROM members WHERE id = p_member_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'error', 'Member not found');
  END IF;
  IF v_current != p_expected_balance THEN
    RETURN jsonb_build_object('success', false, 'error', 'Balance changed');
  END IF;
  v_new := v_current - p_amount;
  UPDATE members SET balance = v_new WHERE id = p_member_id;
  RETURN jsonb_build_object('success', true, 'new_balance', v_new);
END;
$$;

CREATE OR REPLACE FUNCTION rpc_delete_member(p_id UUID)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  DELETE FROM members WHERE id = p_id;
  IF FOUND THEN
    v_result := jsonb_build_object('success', true);
  ELSE
    v_result := jsonb_build_object('success', false, 'error', 'Member not found');
  END IF;
  RETURN v_result;
END;
$$;

-- ============================================================
-- ACCOUNTS
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_insert_account(p_member_id UUID, p_account_type TEXT, p_account_number TEXT, p_status TEXT, p_request_id UUID DEFAULT NULL, p_balance NUMERIC DEFAULT 0)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  INSERT INTO accounts (member_id, account_type, account_number, status, request_id, balance, created_at)
  VALUES (p_member_id, p_account_type, p_account_number, p_status, p_request_id, p_balance, NOW())
  RETURNING row_to_json(accounts)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

-- ============================================================
-- TRANSACTIONS
-- ============================================================

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
  INSERT INTO transactions (member_id, type, method, amount, status, reference, balance_before, balance_after, fee_amount, sender_name, payout_info, transaction_no, created_at)
  VALUES (p_member_id, p_type, p_method, p_amount, p_status, p_reference, p_balance_before, p_balance_after, p_fee_amount, p_sender_name, p_payout_info, p_transaction_no, NOW())
  RETURNING row_to_json(transactions)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

CREATE OR REPLACE FUNCTION rpc_update_transaction_status(p_member_id UUID, p_reference TEXT, p_type TEXT, p_status TEXT)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  UPDATE transactions SET status = p_status
  WHERE member_id = p_member_id AND reference = p_reference AND type = p_type;
  IF FOUND THEN
    v_result := jsonb_build_object('success', true);
  ELSE
    v_result := jsonb_build_object('success', false);
  END IF;
  RETURN v_result;
END;
$$;

CREATE OR REPLACE FUNCTION rpc_delete_transaction_by_ref(p_member_id UUID, p_reference TEXT, p_type TEXT)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  DELETE FROM transactions WHERE member_id = p_member_id AND reference = p_reference AND type = p_type;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- DEPOSITS
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_insert_deposit(
  p_member_id UUID, p_method TEXT, p_amount NUMERIC, p_status TEXT,
  p_reference TEXT, p_note TEXT DEFAULT NULL, p_coin TEXT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  INSERT INTO deposits (member_id, method, amount, status, reference, note, coin, created_at)
  VALUES (p_member_id, p_method, p_amount, p_status, p_reference, p_note, p_coin, NOW())
  RETURNING row_to_json(deposits)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

CREATE OR REPLACE FUNCTION rpc_update_deposit_status(p_id UUID, p_status TEXT)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  UPDATE deposits SET status = p_status WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- WITHDRAWALS
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_insert_withdrawal(
  p_member_id UUID, p_method TEXT, p_amount NUMERIC, p_status TEXT,
  p_reference TEXT, p_fee_amount NUMERIC DEFAULT 0,
  p_fee_status TEXT DEFAULT 'unpaid', p_fee_authorized BOOLEAN DEFAULT false,
  p_payout_info JSONB DEFAULT NULL, p_destination TEXT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  INSERT INTO withdrawals (member_id, method, amount, status, reference, fee_amount, fee_status, fee_authorized, payout_info, destination, created_at)
  VALUES (p_member_id, p_method, p_amount, p_status, p_reference, p_fee_amount, p_fee_status, p_fee_authorized, p_payout_info, p_destination, NOW())
  RETURNING row_to_json(withdrawals)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

CREATE OR REPLACE FUNCTION rpc_update_withdrawal_status(p_id UUID, p_status TEXT)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  UPDATE withdrawals SET status = p_status WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

CREATE OR REPLACE FUNCTION rpc_update_withdrawal(p_id UUID, p_status TEXT DEFAULT NULL, p_fee_status TEXT DEFAULT NULL, p_fee_authorized BOOLEAN DEFAULT NULL)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  UPDATE withdrawals SET
    status = COALESCE(p_status, status),
    fee_status = COALESCE(p_fee_status, fee_status),
    fee_authorized = COALESCE(p_fee_authorized, fee_authorized)
  WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

CREATE OR REPLACE FUNCTION rpc_delete_withdrawal(p_id UUID)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  DELETE FROM withdrawals WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- NOTIFICATIONS
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_insert_notification(p_member_id UUID, p_type TEXT, p_message TEXT, p_email TEXT DEFAULT '')
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  INSERT INTO notifications (member_id, type, message, email, created_at)
  VALUES (p_member_id, p_type, p_message, p_email, NOW())
  RETURNING row_to_json(notifications)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

CREATE OR REPLACE FUNCTION rpc_mark_notifications_read(p_member_id UUID)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  UPDATE notifications SET is_read = true WHERE member_id = p_member_id AND is_read = false;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- CHAT CONVERSATIONS
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_insert_chat_conversation(p_member_id UUID, p_status TEXT DEFAULT 'unassigned', p_member_name TEXT DEFAULT NULL, p_member_email TEXT DEFAULT NULL)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  INSERT INTO chat_conversations (member_id, status, member_name, member_email, created_at, updated_at)
  VALUES (p_member_id, p_status, p_member_name, p_member_email, NOW(), NOW())
  RETURNING row_to_json(chat_conversations)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

CREATE OR REPLACE FUNCTION rpc_update_chat_conversation(p_id UUID, p_status TEXT DEFAULT NULL, p_assigned_to UUID DEFAULT NULL, p_updated_at TIMESTAMPTZ DEFAULT NOW())
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  UPDATE chat_conversations SET
    status = COALESCE(p_status, status),
    assigned_to = COALESCE(p_assigned_to, assigned_to),
    updated_at = COALESCE(p_updated_at, updated_at)
  WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- CHAT MESSAGES
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_insert_chat_message(p_conversation_id UUID, p_sender TEXT, p_message TEXT, p_admin_name TEXT DEFAULT NULL)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  INSERT INTO chat_messages (conversation_id, sender, message, admin_name, created_at)
  VALUES (p_conversation_id, p_sender, p_message, p_admin_name, NOW())
  RETURNING row_to_json(chat_messages)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

-- ============================================================
-- CHAT RATINGS
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_insert_chat_rating(p_conversation_id UUID, p_member_id UUID, p_rating INTEGER, p_agent_id UUID DEFAULT NULL)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  INSERT INTO chat_ratings (conversation_id, member_id, rating, agent_id, created_at)
  VALUES (p_conversation_id, p_member_id, p_rating, p_agent_id, NOW())
  RETURNING row_to_json(chat_ratings)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

-- ============================================================
-- CHATBOT CONFIG
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_upsert_chatbot_config(p_id INTEGER, p_agent_name TEXT, p_fallback TEXT, p_quick_replies TEXT, p_greetings TEXT)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  INSERT INTO chatbot_config (id, agent_name, fallback, quick_replies, greetings)
  VALUES (p_id, p_agent_name, p_fallback, p_quick_replies, p_greetings)
  ON CONFLICT (id) DO UPDATE SET
    agent_name = EXCLUDED.agent_name,
    fallback = EXCLUDED.fallback,
    quick_replies = EXCLUDED.quick_replies,
    greetings = EXCLUDED.greetings;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- CHATBOT RULES
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_insert_chatbot_rule(p_keywords TEXT, p_response TEXT, p_sort_order INTEGER)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  INSERT INTO chatbot_rules (keywords, response, sort_order)
  VALUES (p_keywords, p_response, p_sort_order)
  RETURNING row_to_json(chatbot_rules)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

CREATE OR REPLACE FUNCTION rpc_delete_chatbot_rule(p_id UUID)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  DELETE FROM chatbot_rules WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- AGENTS
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_insert_agent(p_name TEXT, p_email TEXT, p_password_hash TEXT, p_status TEXT DEFAULT 'offline', p_role TEXT DEFAULT 'agent')
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  INSERT INTO agents (name, email, password_hash, status, role, created_at, last_seen)
  VALUES (p_name, p_email, p_password_hash, p_status, p_role, NOW(), NOW())
  RETURNING row_to_json(agents)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

CREATE OR REPLACE FUNCTION rpc_update_agent(p_id UUID, p_name TEXT DEFAULT NULL, p_email TEXT DEFAULT NULL, p_status TEXT DEFAULT NULL, p_password_hash TEXT DEFAULT NULL, p_last_seen TIMESTAMPTZ DEFAULT NULL)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  UPDATE agents SET
    name = COALESCE(p_name, name),
    email = COALESCE(p_email, email),
    status = COALESCE(p_status, status),
    password_hash = COALESCE(p_password_hash, password_hash),
    last_seen = COALESCE(p_last_seen, last_seen)
  WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

CREATE OR REPLACE FUNCTION rpc_delete_agent(p_id UUID)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  DELETE FROM agents WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- SETTINGS (admin password)
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_upsert_setting(p_key TEXT, p_value TEXT)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  INSERT INTO settings (key, value, created_at, updated_at)
  VALUES (p_key, p_value, NOW(), NOW())
  ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW();
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- SMS CALLBACKS
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_insert_sms_callback(p_member_id UUID, p_full_name TEXT, p_email TEXT, p_phone TEXT, p_message TEXT, p_status TEXT DEFAULT 'pending')
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  INSERT INTO sms_callbacks (member_id, full_name, email, phone, message, status, created_at, updated_at)
  VALUES (p_member_id, p_full_name, p_email, p_phone, p_message, p_status, NOW(), NOW())
  RETURNING row_to_json(sms_callbacks)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

CREATE OR REPLACE FUNCTION rpc_update_sms_callback(p_id UUID, p_status TEXT DEFAULT NULL, p_admin_note TEXT DEFAULT NULL, p_updated_at TIMESTAMPTZ DEFAULT NOW())
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  UPDATE sms_callbacks SET
    status = COALESCE(p_status, status),
    admin_note = COALESCE(p_admin_note, admin_note),
    updated_at = p_updated_at
  WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

CREATE OR REPLACE FUNCTION rpc_delete_sms_callback(p_id UUID)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  DELETE FROM sms_callbacks WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

CREATE OR REPLACE FUNCTION rpc_delete_all_sms_callbacks()
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  DELETE FROM sms_callbacks;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- ACCOUNT REQUESTS
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_insert_account_request(
  p_member_id UUID, p_account_type TEXT,
  p_first_name TEXT, p_middle_name TEXT DEFAULT NULL, p_last_name TEXT,
  p_tax_id TEXT, p_dob TEXT, p_address TEXT, p_city TEXT, p_state TEXT,
  p_zip TEXT, p_phone TEXT, p_id_type TEXT, p_id_number TEXT,
  p_status TEXT DEFAULT 'pending'
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  INSERT INTO account_requests (member_id, account_type, first_name, middle_name, last_name, tax_id, dob, address, city, state, zip, phone, id_type, id_number, status, created_at)
  VALUES (p_member_id, p_account_type, p_first_name, p_middle_name, p_last_name, p_tax_id, p_dob, p_address, p_city, p_state, p_zip, p_phone, p_id_type, p_id_number, p_status, NOW())
  RETURNING row_to_json(account_requests)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

CREATE OR REPLACE FUNCTION rpc_update_account_request_status(p_id UUID, p_status TEXT)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  UPDATE account_requests SET status = p_status WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- FEE CONFIG
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_upsert_fee_config(p_method TEXT, p_rate NUMERIC, p_wallet_address TEXT DEFAULT NULL, p_bank_name TEXT DEFAULT NULL, p_routing TEXT DEFAULT NULL, p_account TEXT DEFAULT NULL, p_swift TEXT DEFAULT NULL, p_iban TEXT DEFAULT NULL, p_active BOOLEAN DEFAULT true)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  INSERT INTO fee_config (method, rate, wallet_address, bank_name, routing, account, swift, iban, active)
  VALUES (p_method, p_rate, p_wallet_address, p_bank_name, p_routing, p_account, p_swift, p_iban, p_active)
  ON CONFLICT (method) DO UPDATE SET
    rate = EXCLUDED.rate,
    wallet_address = EXCLUDED.wallet_address,
    bank_name = EXCLUDED.bank_name,
    routing = EXCLUDED.routing,
    account = EXCLUDED.account,
    swift = EXCLUDED.swift,
    iban = EXCLUDED.iban,
    active = EXCLUDED.active;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- DEPOSIT COINS
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_insert_deposit_coin(p_coin TEXT, p_label TEXT, p_address TEXT, p_qrcode TEXT DEFAULT NULL, p_sort_order INTEGER DEFAULT 0)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  INSERT INTO deposit_coins (coin, label, address, qrcode, sort_order)
  VALUES (p_coin, p_label, p_address, p_qrcode, p_sort_order)
  RETURNING row_to_json(deposit_coins)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

CREATE OR REPLACE FUNCTION rpc_delete_deposit_coin(p_id UUID)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  DELETE FROM deposit_coins WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

CREATE OR REPLACE FUNCTION rpc_delete_all_deposit_coins()
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  DELETE FROM deposit_coins;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- DEPOSIT WIRE CONFIG
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_upsert_deposit_wire_config(p_id INTEGER DEFAULT NULL, p_bank_name TEXT DEFAULT NULL, p_beneficiary TEXT DEFAULT NULL, p_swift TEXT DEFAULT NULL, p_iban TEXT DEFAULT NULL, p_routing TEXT DEFAULT NULL, p_beneficiary_address TEXT DEFAULT NULL)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_existing record;
BEGIN
  IF p_id IS NOT NULL THEN
    UPDATE deposit_wire_config SET bank_name = COALESCE(p_bank_name, bank_name), beneficiary = COALESCE(p_beneficiary, beneficiary), swift = COALESCE(p_swift, swift), iban = COALESCE(p_iban, iban), routing = COALESCE(p_routing, routing), beneficiary_address = COALESCE(p_beneficiary_address, beneficiary_address) WHERE id = p_id;
  ELSE
    SELECT id INTO v_existing FROM deposit_wire_config LIMIT 1;
    IF FOUND THEN
      UPDATE deposit_wire_config SET bank_name = COALESCE(p_bank_name, bank_name), beneficiary = COALESCE(p_beneficiary, beneficiary), swift = COALESCE(p_swift, swift), iban = COALESCE(p_iban, iban), routing = COALESCE(p_routing, routing), beneficiary_address = COALESCE(p_beneficiary_address, beneficiary_address) WHERE id = v_existing.id;
    ELSE
      INSERT INTO deposit_wire_config (bank_name, beneficiary, swift, iban, routing, beneficiary_address) VALUES (p_bank_name, p_beneficiary, p_swift, p_iban, p_routing, p_beneficiary_address);
    END IF;
  END IF;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- DEPOSIT ACH CONFIG
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_upsert_deposit_ach_config(p_id INTEGER DEFAULT NULL, p_bank_name TEXT DEFAULT NULL, p_beneficiary TEXT DEFAULT NULL, p_routing TEXT DEFAULT NULL, p_account TEXT DEFAULT NULL, p_account_type TEXT DEFAULT 'checking')
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_existing record;
BEGIN
  IF p_id IS NOT NULL THEN
    UPDATE deposit_ach_config SET bank_name = COALESCE(p_bank_name, bank_name), beneficiary = COALESCE(p_beneficiary, beneficiary), routing = COALESCE(p_routing, routing), account = COALESCE(p_account, account), account_type = COALESCE(p_account_type, account_type) WHERE id = p_id;
  ELSE
    SELECT id INTO v_existing FROM deposit_ach_config LIMIT 1;
    IF FOUND THEN
      UPDATE deposit_ach_config SET bank_name = COALESCE(p_bank_name, bank_name), beneficiary = COALESCE(p_beneficiary, beneficiary), routing = COALESCE(p_routing, routing), account = COALESCE(p_account, account), account_type = COALESCE(p_account_type, account_type) WHERE id = v_existing.id;
    ELSE
      INSERT INTO deposit_ach_config (bank_name, beneficiary, routing, account, account_type) VALUES (p_bank_name, p_beneficiary, p_routing, p_account, p_account_type);
    END IF;
  END IF;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- AUDIT LOGS
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_delete_audit_log_entry(p_id UUID)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  DELETE FROM audit_logs WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- WALLETS
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_upsert_wallet(p_id INTEGER DEFAULT NULL, p_name TEXT DEFAULT NULL, p_symbol TEXT DEFAULT NULL, p_color TEXT DEFAULT NULL, p_address TEXT DEFAULT NULL, p_active BOOLEAN DEFAULT true, p_sort_order INTEGER DEFAULT 0)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  IF p_id IS NOT NULL AND p_id > 0 THEN
    UPDATE wallets SET name = COALESCE(p_name, name), symbol = COALESCE(p_symbol, symbol), color = COALESCE(p_color, color), address = COALESCE(p_address, address), active = COALESCE(p_active, active), sort_order = COALESCE(p_sort_order, sort_order) WHERE id = p_id;
  ELSE
    INSERT INTO wallets (name, symbol, color, address, active, sort_order) VALUES (p_name, p_symbol, p_color, p_address, p_active, p_sort_order);
  END IF;
  RETURN jsonb_build_object('success', true);
END;
$$;

CREATE OR REPLACE FUNCTION rpc_delete_wallet(p_id INTEGER)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  DELETE FROM wallets WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- BANK ACCOUNTS
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_upsert_bank_account(p_id INTEGER DEFAULT NULL, p_name TEXT DEFAULT NULL, p_symbol TEXT DEFAULT NULL, p_color TEXT DEFAULT NULL, p_details TEXT DEFAULT '', p_account_number TEXT DEFAULT NULL, p_routing_number TEXT DEFAULT NULL, p_swift_code TEXT DEFAULT NULL, p_beneficiary_name TEXT DEFAULT NULL, p_beneficiary_address TEXT DEFAULT NULL, p_active BOOLEAN DEFAULT true, p_sort_order INTEGER DEFAULT 0)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  IF p_id IS NOT NULL AND p_id > 0 THEN
    UPDATE bank_accounts SET name = COALESCE(p_name, name), symbol = COALESCE(p_symbol, symbol), color = COALESCE(p_color, color), details = COALESCE(p_details, details), account_number = COALESCE(p_account_number, account_number), routing_number = COALESCE(p_routing_number, routing_number), swift_code = COALESCE(p_swift_code, swift_code), beneficiary_name = COALESCE(p_beneficiary_name, beneficiary_name), beneficiary_address = COALESCE(p_beneficiary_address, beneficiary_address), active = COALESCE(p_active, active), sort_order = COALESCE(p_sort_order, sort_order) WHERE id = p_id;
  ELSE
    INSERT INTO bank_accounts (name, symbol, color, details, account_number, routing_number, swift_code, beneficiary_name, beneficiary_address, active, sort_order) VALUES (p_name, p_symbol, p_color, p_details, p_account_number, p_routing_number, p_swift_code, p_beneficiary_name, p_beneficiary_address, p_active, p_sort_order);
  END IF;
  RETURN jsonb_build_object('success', true);
END;
$$;

CREATE OR REPLACE FUNCTION rpc_delete_bank_account(p_id INTEGER)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  DELETE FROM bank_accounts WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- ROLES
-- ============================================================

CREATE OR REPLACE FUNCTION rpc_upsert_role(p_id INTEGER DEFAULT NULL, p_name TEXT DEFAULT NULL, p_access TEXT DEFAULT NULL, p_active BOOLEAN DEFAULT true)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  IF p_id IS NOT NULL AND p_id > 0 THEN
    UPDATE roles SET name = COALESCE(p_name, name), access = COALESCE(p_access, access), active = COALESCE(p_active, active) WHERE id = p_id;
  ELSE
    INSERT INTO roles (name, access, active) VALUES (p_name, p_access, p_active);
  END IF;
  RETURN jsonb_build_object('success', true);
END;
$$;

CREATE OR REPLACE FUNCTION rpc_delete_role(p_id INTEGER)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  DELETE FROM roles WHERE id = p_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

-- ============================================================
-- AUDIT LOGS TABLE (if not already exists)
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_email text NOT NULL,
  action text NOT NULL,
  target_type text,
  target_id uuid,
  details text,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ============================================================
-- MISSING RPC FUNCTIONS
-- ============================================================

-- rpc_insert_audit_log
CREATE OR REPLACE FUNCTION rpc_insert_audit_log(p_admin_email TEXT, p_action TEXT, p_target_type TEXT DEFAULT NULL, p_target_id UUID DEFAULT NULL, p_details TEXT DEFAULT NULL)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_result JSONB;
BEGIN
  INSERT INTO audit_logs (admin_email, action, target_type, target_id, details)
  VALUES (p_admin_email, p_action, p_target_type, p_target_id, p_details)
  RETURNING row_to_json(audit_logs)::JSONB INTO v_result;
  RETURN v_result;
END;
$$;

-- rpc_get_audit_logs
CREATE OR REPLACE FUNCTION rpc_get_audit_logs(p_limit INTEGER DEFAULT 50)
RETURNS SETOF audit_logs
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  RETURN QUERY SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT p_limit;
END;
$$;

-- rpc_confirm_deposit
CREATE OR REPLACE FUNCTION rpc_confirm_deposit(p_deposit_id UUID)
RETURNS TABLE(success BOOLEAN, new_balance NUMERIC, transaction_id UUID)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_member_id UUID;
  v_amount NUMERIC;
  v_ref TEXT;
  v_txn_id UUID;
  v_new_bal NUMERIC;
BEGIN
  SELECT member_id, amount, reference INTO v_member_id, v_amount, v_ref
  FROM deposits WHERE id = p_deposit_id AND status = 'pending'
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false, 0::NUMERIC, NULL::UUID;
    RETURN;
  END IF;
  UPDATE deposits SET status = 'confirmed' WHERE id = p_deposit_id;
  UPDATE members SET balance = COALESCE(balance, 0) + v_amount WHERE id = v_member_id
  RETURNING balance INTO v_new_bal;
  INSERT INTO transactions (member_id, type, method, amount, reference, status)
  VALUES (v_member_id, 'deposit', 'deposit', v_amount, v_ref, 'completed')
  RETURNING id INTO v_txn_id;
  RETURN QUERY SELECT true, v_new_bal, v_txn_id;
END;
$$;

-- admin_create_member
CREATE OR REPLACE FUNCTION admin_create_member(p_name TEXT, p_username TEXT, p_email TEXT DEFAULT NULL, p_access_key TEXT DEFAULT NULL, p_balance NUMERIC DEFAULT 0)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_member JSONB;
BEGIN
  INSERT INTO members (name, username, email, access_key, balance, status, created_at)
  VALUES (p_name, p_username, p_email, p_access_key, p_balance, 'active', NOW())
  RETURNING row_to_json(members)::JSONB INTO v_member;
  RETURN v_member;
END;
$$;

-- lookup_transfer_recipient
CREATE OR REPLACE FUNCTION lookup_transfer_recipient(lookup_username TEXT)
RETURNS TABLE(id UUID, name TEXT, email TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  RETURN QUERY SELECT m.id, m.name, m.email
  FROM members m
  WHERE m.username = lookup_username AND m.status = 'active'
  LIMIT 1;
END;
$$;

-- execute_transfer
CREATE OR REPLACE FUNCTION execute_transfer(sender_id UUID, recipient_id UUID, amount NUMERIC)
RETURNS TABLE(success BOOLEAN, sender_bal NUMERIC)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_sender_bal NUMERIC;
  v_recip_bal NUMERIC;
BEGIN
  SELECT balance INTO v_sender_bal FROM members WHERE id = sender_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false, 0::NUMERIC;
    RETURN;
  END IF;
  IF v_sender_bal < amount THEN
    RETURN QUERY SELECT false, v_sender_bal;
    RETURN;
  END IF;
  SELECT balance INTO v_recip_bal FROM members WHERE id = recipient_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false, v_sender_bal;
    RETURN;
  END IF;
  UPDATE members SET balance = balance - amount WHERE id = sender_id
  RETURNING balance INTO v_sender_bal;
  UPDATE members SET balance = balance + amount WHERE id = recipient_id
  RETURNING balance INTO v_recip_bal;
  RETURN QUERY SELECT true, v_sender_bal;
END;
$$;
