-- Agent pool for live chat
CREATE TABLE IF NOT EXISTS agents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  status TEXT DEFAULT 'offline' CHECK (status IN ('online','offline','busy')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  last_seen TIMESTAMPTZ DEFAULT NOW()
);

-- Add assigned_to to chat_conversations if not exists
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='chat_conversations' AND column_name='assigned_to') THEN
    ALTER TABLE chat_conversations ADD COLUMN assigned_to UUID REFERENCES agents(id);
  END IF;
END $$;

-- Seed default agent from existing admin settings
INSERT INTO agents (name, email, password_hash, status)
SELECT 'Admin', 'admin@secure.metasbank', value, 'offline'
FROM settings WHERE key = 'admin_password_hash'
ON CONFLICT (email) DO NOTHING;

-- Enable realtime for agents table
ALTER PUBLICATION supabase_realtime ADD TABLE agents;
