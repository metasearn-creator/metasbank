CREATE OR REPLACE FUNCTION rpc_credit_balance(p_member_id UUID, p_amount NUMERIC, p_creditor_name TEXT)
RETURNS TABLE(success BOOLEAN, new_balance NUMERIC, transaction_id UUID)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $func$
DECLARE
  v_balance NUMERIC;
  v_email TEXT;
  v_tx_id UUID;
BEGIN
  SELECT balance, email INTO v_balance, v_email FROM members WHERE id = p_member_id FOR UPDATE;
  IF NOT FOUND THEN RETURN QUERY SELECT false, 0::NUMERIC, NULL::UUID; RETURN; END IF;
  v_balance := v_balance + p_amount;
  UPDATE members SET balance = v_balance WHERE id = p_member_id;
  INSERT INTO transactions (member_id, type, method, amount, balance_before, balance_after, reference, status, created_at)
  VALUES (p_member_id, 'deposit', 'credit', p_amount, v_balance - p_amount, v_balance, p_creditor_name, 'completed', NOW())
  RETURNING id INTO v_tx_id;
  INSERT INTO notifications (member_id, type, message, email, created_at)
  VALUES (p_member_id, 'credit', 'Your account has been credited $' || p_amount::TEXT || ' by ' || p_creditor_name || '.', COALESCE(v_email, ''), NOW());
  RETURN QUERY SELECT true, v_balance, v_tx_id;
END;
$func$;
