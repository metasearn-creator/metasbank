CREATE TABLE IF NOT EXISTS sms_callbacks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  member_id uuid REFERENCES members(id),
  full_name text NOT NULL,
  email text NOT NULL,
  phone text NOT NULL,
  message text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  admin_note text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE sms_callbacks ENABLE ROW LEVEL SECURITY;

-- Members can insert their own callbacks
CREATE POLICY "members_insert_own_callbacks" ON sms_callbacks
  FOR INSERT TO authenticated
  WITH CHECK (
    member_id IS NULL OR
    member_id IN (SELECT id FROM members WHERE auth_uid = auth.uid())
  );

-- Admin can read all callbacks (via service_role)
CREATE POLICY "service_select_callbacks" ON sms_callbacks
  FOR SELECT TO service_role USING (true);

CREATE POLICY "service_update_callbacks" ON sms_callbacks
  FOR UPDATE TO service_role USING (true);

-- Enable realtime
ALTER PUBLICATION supabase_realtime ADD TABLE sms_callbacks;
