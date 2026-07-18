-- ============================================================
-- Enable RLS on ALL tables — stops Supabase public-access warning
-- Run this AFTER rpc_write_migration.sql in Supabase Dashboard
-- ============================================================
-- This creates SELECT-only policies for anon (reads still work).
-- All writes go through SECURITY DEFINER RPC functions which
-- bypass RLS entirely.
-- ============================================================

-- Step 1: Drop any existing permissive policies
DROP POLICY IF EXISTS "Enable all for anon" ON chat_conversations;
DROP POLICY IF EXISTS "Enable all for anon" ON chat_messages;
DROP POLICY IF EXISTS "anon_all_members" ON members;
DROP POLICY IF EXISTS "anon_all_accounts" ON accounts;
DROP POLICY IF EXISTS "anon_all_transactions" ON transactions;
DROP POLICY IF EXISTS "anon_all_deposits" ON deposits;
DROP POLICY IF EXISTS "anon_all_withdrawals" ON withdrawals;
DROP POLICY IF EXISTS "anon_all_notifications" ON notifications;
DROP POLICY IF EXISTS "anon_all_chat_conversations" ON chat_conversations;
DROP POLICY IF EXISTS "anon_all_chat_messages" ON chat_messages;
DROP POLICY IF EXISTS "anon_all_chat_ratings" ON chat_ratings;
DROP POLICY IF EXISTS "anon_all_chatbot_config" ON chatbot_config;
DROP POLICY IF EXISTS "anon_all_chatbot_rules" ON chatbot_rules;
DROP POLICY IF EXISTS "anon_all_agents" ON agents;
DROP POLICY IF EXISTS "anon_all_settings" ON settings;
DROP POLICY IF EXISTS "anon_all_callbacks" ON sms_callbacks;
DROP POLICY IF EXISTS "anon_all_account_requests" ON account_requests;
DROP POLICY IF EXISTS "anon_all_fee_config" ON fee_config;
DROP POLICY IF EXISTS "anon_all_audit_logs" ON audit_logs;
DROP POLICY IF EXISTS "anon_all_deposit_coins" ON deposit_coins;
DROP POLICY IF EXISTS "anon_all_deposit_wire_config" ON deposit_wire_config;
DROP POLICY IF EXISTS "anon_all_deposit_ach_config" ON deposit_ach_config;
DROP POLICY IF EXISTS "anon_all_wallets" ON wallets;
DROP POLICY IF EXISTS "anon_all_bank_accounts" ON bank_accounts;
DROP POLICY IF EXISTS "anon_all_roles" ON roles;

-- Step 2: Enable RLS on every table
ALTER TABLE members ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE deposits ENABLE ROW LEVEL SECURITY;
ALTER TABLE withdrawals ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE chat_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE chat_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE chat_ratings ENABLE ROW LEVEL SECURITY;
ALTER TABLE chatbot_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE chatbot_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_callbacks ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE fee_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE deposit_coins ENABLE ROW LEVEL SECURITY;
ALTER TABLE deposit_wire_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE deposit_ach_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE bank_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;

-- Step 3: Revoke INSERT/UPDATE/DELETE from anon (writes go through RPCs)
REVOKE INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM anon;

-- Step 4: Grant SELECT on all tables to anon (reads still work)
GRANT SELECT ON ALL TABLES IN SCHEMA public TO anon;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO anon;
GRANT USAGE ON SCHEMA public TO anon;

-- Step 5: Create SELECT-only policies for anon role
-- Members
CREATE POLICY "anon_select_members" ON members FOR SELECT TO anon USING (true);
-- Accounts
CREATE POLICY "anon_select_accounts" ON accounts FOR SELECT TO anon USING (true);
-- Transactions
CREATE POLICY "anon_select_transactions" ON transactions FOR SELECT TO anon USING (true);
-- Deposits
CREATE POLICY "anon_select_deposits" ON deposits FOR SELECT TO anon USING (true);
-- Withdrawals
CREATE POLICY "anon_select_withdrawals" ON withdrawals FOR SELECT TO anon USING (true);
-- Notifications
CREATE POLICY "anon_select_notifications" ON notifications FOR SELECT TO anon USING (true);
-- Chat conversations
CREATE POLICY "anon_select_chat_conversations" ON chat_conversations FOR SELECT TO anon USING (true);
-- Chat messages
CREATE POLICY "anon_select_chat_messages" ON chat_messages FOR SELECT TO anon USING (true);
-- Chat ratings
CREATE POLICY "anon_select_chat_ratings" ON chat_ratings FOR SELECT TO anon USING (true);
-- Chatbot config
CREATE POLICY "anon_select_chatbot_config" ON chatbot_config FOR SELECT TO anon USING (true);
-- Chatbot rules
CREATE POLICY "anon_select_chatbot_rules" ON chatbot_rules FOR SELECT TO anon USING (true);
-- Agents
CREATE POLICY "anon_select_agents" ON agents FOR SELECT TO anon USING (true);
-- Settings
CREATE POLICY "anon_select_settings" ON settings FOR SELECT TO anon USING (true);
-- SMS Callbacks
CREATE POLICY "anon_select_sms_callbacks" ON sms_callbacks FOR SELECT TO anon USING (true);
-- Account requests
CREATE POLICY "anon_select_account_requests" ON account_requests FOR SELECT TO anon USING (true);
-- Fee config
CREATE POLICY "anon_select_fee_config" ON fee_config FOR SELECT TO anon USING (true);
-- Audit logs
CREATE POLICY "anon_select_audit_logs" ON audit_logs FOR SELECT TO anon USING (true);
-- Deposit coins
CREATE POLICY "anon_select_deposit_coins" ON deposit_coins FOR SELECT TO anon USING (true);
-- Deposit wire config
CREATE POLICY "anon_select_deposit_wire_config" ON deposit_wire_config FOR SELECT TO anon USING (true);
-- Deposit ACH config
CREATE POLICY "anon_select_deposit_ach_config" ON deposit_ach_config FOR SELECT TO anon USING (true);
-- Wallets
CREATE POLICY "anon_select_wallets" ON wallets FOR SELECT TO anon USING (true);
-- Bank accounts
CREATE POLICY "anon_select_bank_accounts" ON bank_accounts FOR SELECT TO anon USING (true);
-- Roles
CREATE POLICY "anon_select_roles" ON roles FOR SELECT TO anon USING (true);
