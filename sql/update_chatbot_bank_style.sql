-- Update chatbot_config with bank-style female agent
UPDATE chatbot_config SET
  agent_name = 'Sarah',
  fallback = 'I&#39;m sorry, I didn&#39;t quite understand. Please try asking about <b>withdrawals</b>, <b>deposits</b>, <b>fees</b>, or <b>balance</b>. You may also type <b>agent</b> to speak with a representative.',
  quick_replies = 'Withdraw help,Deposit info,Fee schedule,My balance,Speak to agent',
  greetings = 'Welcome to MetasBank. How may I assist you with your banking today?'
WHERE id = 1;

-- Delete old rules and replace with bank-style ones
DELETE FROM chatbot_rules;

-- balance
INSERT INTO chatbot_rules (id, keywords, response, sort_order)
VALUES (gen_random_uuid(), 'balance,my balance,available balance,how much,account balance,check balance',
'Your current available balance is displayed on your dashboard. For transaction details, please refer to your statements.', 1);

-- deposit
INSERT INTO chatbot_rules (id, keywords, response, sort_order)
VALUES (gen_random_uuid(), 'deposit,deposit funds,add funds,funding,credit,pay in',
'To deposit funds, navigate to the <b>Deposit</b> tab and select your preferred method — Crypto, ACH, or Wire. Follow the instructions provided and confirm once the transfer is initiated.', 2);

-- withdraw
INSERT INTO chatbot_rules (id, keywords, response, sort_order)
VALUES (gen_random_uuid(), 'withdraw,how to withdraw,withdrawal,payout,cash out,take out,withdraw funds',
'Withdrawals are processed in 3 steps:<br><br>1. <b>Submit Request</b> — Enter the amount and select your payout method.<br>2. <b>Processing Fee</b> — Review and pay the applicable fee.<br>3. <b>Approval</b> — Our team reviews and releases your funds.<br><br>You can start from the <b>Withdraw</b> tab on your dashboard.', 3);

-- fees
INSERT INTO chatbot_rules (id, keywords, response, sort_order)
VALUES (gen_random_uuid(), 'fee,fees,processing fee,service fee,charge,charges,fee schedule,cost',
'Our processing fees are as follows:<br><br>• <b>Crypto</b> — 1% (min $50)<br>• <b>ACH</b> — 3.2% (min $200)<br>• <b>Wire</b> — 20% (min $500)<br><br>Fees are displayed before you confirm your withdrawal.', 4);

-- pending status
INSERT INTO chatbot_rules (id, keywords, response, sort_order)
VALUES (gen_random_uuid(), 'pending,stuck,transaction id,transaction ID,txn,withdrawal id,reference,status,review,processing time,how long',
'Most withdrawals are reviewed within 24 hours. You will receive a notification once your transaction has been processed. If you need urgent assistance, please request to speak with an agent.', 5);

-- agent transfer
INSERT INTO chatbot_rules (id, keywords, response, sort_order)
VALUES (gen_random_uuid(), 'agent,human,speak,transfer,talk to,representative,escalate,person,real person,Yomi,Sarah',
'I am connecting you to <b>Sarah</b>, a member of our support team. Please hold while she reviews your request.', 6);

-- thanks
INSERT INTO chatbot_rules (id, keywords, response, sort_order)
VALUES (gen_random_uuid(), 'thank,thanks,appreciate,thank you',
'You are most welcome. If you require any further assistance, please do not hesitate to reach out. We are here to help.', 7);

-- greetings
INSERT INTO chatbot_rules (id, keywords, response, sort_order)
VALUES (gen_random_uuid(), 'hello,hi,hey,help,start,begin,assist,good morning,good afternoon,good evening',
'Good day. I am Sarah, your MetasBank assistant. I can help you with withdrawals, deposits, fees, balance inquiries, and more. Please let me know how I may assist you.', 8);
