# MetasBank — Checkpoint
## Developer: GARZA

## What's been done
- **RLS migration** (`sql/rpc_write_migration.sql`): ~36 SECURITY DEFINER functions for all writes
- **RLS policies** (`sql/enable_rls.sql`): SELECT-only for anon, permissive policies dropped
- **supabase-config.js**: `rpcInsert/rpcUpdate/rpcDelete/rpc_upsert` helpers added
- **All 3 HTML files**: 89 direct write calls converted to `.rpc()` calls
  - metasbank-member.html: 21 calls
  - metasbank-agent.html: 11 calls
  - metasbank-admin.html: 57 calls

## Deploy steps (on your VM)
1. Copy this folder to VM
2. Run SQL in Supabase SQL Editor: `sql/rpc_write_migration.sql`
3. Run RLS: `sql/enable_rls.sql`
4. Deploy to Vercel (or whatever host): `npx vercel --prod`

## Supabase project (unchanged)
- URL: https://pkhftlbacapcarwnrhzn.supabase.co
- Anon key in `supabase-config.js`

## Hosting
- Domain: metasbank.xo.je
- Old host (InfinityFree) was fail2ban-locked

## What to continue
- Deploy to Vercel
- Map domain metasbank.xo.je to Vercel
- Test all functionality
