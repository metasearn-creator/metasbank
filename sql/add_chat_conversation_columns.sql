-- Add member_name and member_email to chat_conversations
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='chat_conversations' AND column_name='member_name') THEN
    ALTER TABLE chat_conversations ADD COLUMN member_name TEXT;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='chat_conversations' AND column_name='member_email') THEN
    ALTER TABLE chat_conversations ADD COLUMN member_email TEXT;
  END IF;
END $$;
