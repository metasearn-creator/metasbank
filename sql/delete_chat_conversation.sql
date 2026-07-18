CREATE OR REPLACE FUNCTION delete_chat_conversation(p_conv_id UUID)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  DELETE FROM chat_messages WHERE conversation_id = p_conv_id;
  DELETE FROM chat_conversations WHERE id = p_conv_id;
END;
$$;
