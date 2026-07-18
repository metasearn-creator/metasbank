-- Run this in Supabase Dashboard SQL Editor
-- Creates an RPC function that deletes a member and all related data
-- Uses SECURITY DEFINER so it runs with full permissions (bypasses RLS)

CREATE OR REPLACE FUNCTION admin_delete_member(p_member_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_result JSONB;
  v_conversation_ids UUID[];
BEGIN
  -- Collect chat conversation IDs for this member
  SELECT ARRAY_AGG(id) INTO v_conversation_ids
  FROM chat_conversations
  WHERE member_id = p_member_id;

  -- Delete chat messages and ratings for those conversations
  IF v_conversation_ids IS NOT NULL THEN
    DELETE FROM chat_messages WHERE conversation_id = ANY(v_conversation_ids);
    DELETE FROM chat_ratings WHERE conversation_id = ANY(v_conversation_ids);
  END IF;

  -- Delete all related data
  DELETE FROM chat_conversations WHERE member_id = p_member_id;
  DELETE FROM sms_callbacks WHERE member_id = p_member_id;
  DELETE FROM notifications WHERE member_id = p_member_id;
  DELETE FROM account_requests WHERE member_id = p_member_id;
  DELETE FROM accounts WHERE member_id = p_member_id;
  DELETE FROM withdrawals WHERE member_id = p_member_id;
  DELETE FROM deposits WHERE member_id = p_member_id;
  DELETE FROM transactions WHERE member_id = p_member_id;

  -- Delete the member
  DELETE FROM members WHERE id = p_member_id;

  IF FOUND THEN
    v_result := jsonb_build_object('success', true, 'message', 'Member deleted');
  ELSE
    v_result := jsonb_build_object('success', false, 'message', 'Member not found');
  END IF;

  RETURN v_result;
END;
$$;
