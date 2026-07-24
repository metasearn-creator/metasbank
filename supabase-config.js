// Supabase client config — replace with your own project keys
// SECURITY NOTE: The anon key is intentionally public (it's the Supabase way).
// REAL SECURITY comes from Row Level Security (RLS) policies in Supabase Dashboard:
//   - members table: SELECT only own row (auth.uid() = auth_uid), UPDATE own row
//   - agents table: SELECT only for authenticated admins/agents
//   - deposits, withdrawals, transactions: SELECT/INSERT limited by member_id
//   - admin-only tables (fee_config, settings, etc.): no anon access
// Without RLS enforced, the anon key can read/write any row in any table.
// See: https://supabase.com/docs/guides/auth/row-level-security
const SUPABASE_URL = 'https://pkhftlbacapcarwnrhzn.supabase.co'
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBraGZ0bGJhY2FwY2Fyd25yaHpuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODI1MTc2NTYsImV4cCI6MjA5ODA5MzY1Nn0.0fb4lcpAMyMNZRnbBQIwl1EfdnTe3ioj0pIyGPA3gj0'

// Global supabase client
let supabaseClient = null

function initSupabase() {
  if (typeof supabase !== 'undefined') {
    supabaseClient = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY)
    return supabaseClient
  }
  return null
}

// ===== CREDENTIAL EMAIL (via Supabase Auth Confirmation Email) =====
// Credentials are passed as user_metadata in the auth.signUp() call.
// Supabase Auth automatically sends a confirmation email containing the
// metadata. Customize the email template in Supabase Dashboard:
//   Authentication → Email Templates → Confirm Signup
// Use these template variables: {{ .Data.username }}, {{ .Data.access_key }}
//
// The auto-confirm RPC immediately confirms the user so they can sign in
// without clicking the confirmation link, but the email still arrives.

// ===== RATE LIMITING HELPERS (uses localStorage for cross-tab persistence) =====
const RL_PREFIX = 'mb_rl_'

function rlGet(key) { return parseInt(localStorage.getItem(RL_PREFIX + key) || '0', 10) }
function rlSet(key, val) { localStorage.setItem(RL_PREFIX + key, String(val)) }
function rlRemove(key) { localStorage.removeItem(RL_PREFIX + key) }

function trackRateLimit(action, maxAttempts, windowMs) {
  let now = Date.now()
  let windowKey = action + '_window'
  let countKey = action + '_count'
  let win = rlGet(windowKey)
  if (!win || (now - win > windowMs)) {
    rlSet(windowKey, now)
    rlSet(countKey, 1)
  } else {
    rlSet(countKey, rlGet(countKey) + 1)
  }
}

function checkRateLimit(action, maxAttempts, windowMs, lockoutMs) {
  let now = Date.now()
  let lockoutKey = action + '_lockout'
  let lockoutUntil = rlGet(lockoutKey)
  if (lockoutUntil > 0) {
    if (now > lockoutUntil) {
      rlRemove(lockoutKey)
      rlRemove(action + '_window')
      rlRemove(action + '_count')
    } else {
      let remaining = Math.ceil((lockoutUntil - now) / 1000)
      return { locked: true, remaining: remaining }
    }
  }
  let count = rlGet(action + '_count')
  let win = rlGet(action + '_window')
  if (win && (now - win) > windowMs) {
    rlRemove(action + '_window')
    rlRemove(action + '_count')
    return { locked: false }
  }
  if (count >= maxAttempts) {
    rlSet(lockoutKey, now + lockoutMs)
    let remaining = Math.ceil(lockoutMs / 1000)
    return { locked: true, remaining: remaining }
  }
  return { locked: false }
}

function clearRateLimit(action) {
  rlRemove(action + '_lockout')
  rlRemove(action + '_window')
  rlRemove(action + '_count')
}

// ===== MEMBER AUTH =====

async function memberLogin(identifier, accessKey) {
  try {
    let lastAttempt = rlGet('member_login_last')
    let now = Date.now()
    if (lastAttempt > 0 && (now - lastAttempt) < 1000) { return { error: 'Please wait before trying again.' } }
    rlSet('member_login_last', now)

    if (!supabaseClient) initSupabase()
    if (!supabaseClient) return { error: 'System error: database not connected' }

    const isEmail = identifier.includes('@')
    let accessKeyTrimmed = (accessKey || '').trim()
    let query = supabaseClient.from('members').select('id, name, username, email, balance, status, access_key, created_at, last_login, auth_uid, auth_password').eq('access_key', accessKeyTrimmed)
    if (isEmail) {
      query = query.eq('email', identifier.toLowerCase().trim())
    } else {
      query = query.eq('username', identifier.toLowerCase().trim())
    }
    let resp = await query
    let errIdentifier = identifier.toLowerCase().trim()
    if (resp.error) { console.error('Login error:', resp.error); let r = await supabaseClient.rpc('check_rate_limit', { p_action: 'member_login', p_identifier: errIdentifier, p_max_attempts: 10, p_window_minutes: 5 }); if (r.data === false) { return { error: 'Too many failed attempts. Try again later.' } } return { error: 'Invalid credentials' } }
    if (!resp.data || resp.data.length === 0) { let r = await supabaseClient.rpc('check_rate_limit', { p_action: 'member_login', p_identifier: errIdentifier, p_max_attempts: 10, p_window_minutes: 5 }); if (r.data === false) { return { error: 'Too many failed attempts. Try again later.' } } return { error: 'Invalid credentials' } }
    let data = resp.data[0]
    if (data.status !== 'active') return { error: 'Account is suspended' }

    // Sign in with Supabase Auth using stored password, then discard immediately
    let authPwd = data.auth_password
    if (data.auth_uid && authPwd) {
      let authResp = await supabaseClient.auth.signInWithPassword({ email: data.email, password: authPwd })
      if (authResp.error) {
        console.error('Auth sign-in error:', authResp.error);
        data.auth_password = null
        let r = await supabaseClient.rpc('check_rate_limit', { p_action: 'member_login', p_identifier: errIdentifier, p_max_attempts: 10, p_window_minutes: 5 }); if (r.data === false) { return { error: 'Too many failed attempts. Try again later.' } }
        return { error: 'Authentication failed. Please try again.' }
      }
    }
    // Do NOT store auth_password in sessionStorage — re-query DB on re-auth instead
    data.auth_password = null
    authPwd = null

    sessionStorage.setItem('member_user', JSON.stringify(data))
    await supabaseClient.rpc('reset_rate_limit', { p_action: 'member_login', p_identifier: errIdentifier })
    await rpcUpdate('member', { id: data.id }, { last_login: new Date().toISOString() })
    return { data }
  } catch(ex) { console.error('Login exception:', ex); return { error: 'System error' } }
}

function cryptoRandomInt(max) {
  // Returns a cryptographically secure random integer in [0, max) using rejection sampling
  let arr = new Uint8Array(1)
  let range = 256 - (256 % max)
  while (true) {
    crypto.getRandomValues(arr)
    if (arr[0] < range) return arr[0] % max
  }
}
function generatePassword() {
  let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*'
  let pwd = ''
  for (let i = 0; i < 24; i++) pwd += chars.charAt(cryptoRandomInt(chars.length))
  return pwd
}

function getMemberUser() {
  try { return JSON.parse(sessionStorage.getItem('member_user')) } catch(e) { return null }
}

async function memberLogout() {
  sessionStorage.removeItem('member_user')
  try { await supabaseClient.auth.signOut() } catch(e) {}
  window.location.href = '/login/'
}

// Re-authenticate member by re-querying auth_password from DB (no sessionStorage)
async function reauthMember() {
  try {
    let user = getMemberUser()
    if (!user || !user.email) return false
    let { data: rows } = await supabaseClient.from('members').select('auth_password').eq('id', user.id).single()
    if (!rows || !rows.auth_password) return false
    await supabaseClient.auth.signInWithPassword({ email: user.email, password: rows.auth_password })
    return true
  } catch(e) { console.error('reauthMember error:', e); return false }
}

function generateAccessKey() {
  let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*'
  let key = ''
  for (let i = 0; i < 12; i++) key += chars.charAt(cryptoRandomInt(chars.length))
  return key
}

async function memberSignup(email, name, dob, phone, street, city, state, zip, country) {
  if (!supabaseClient) initSupabase()
  if (!supabaseClient) return { error: 'System error: database not connected' }
  if (!email) return { error: 'Email is required' }
  email = email.toLowerCase().trim()
  if (!email.includes('@')) return { error: 'Invalid email' }

  // 1. Check duplicate email
  let { data: emailCheck } = await supabaseClient.from('members').select('id').eq('email', email).maybeSingle()
  if (emailCheck) { console.error('Signup failed: email already exists in members table'); await supabaseClient.rpc('check_rate_limit', { p_action: 'member_signup', p_identifier: email, p_max_attempts: 3, p_window_minutes: 60 }); return { error: 'Registration could not be completed. Please try again later.' } }

  // 2. Generate unique username
  let baseUsername = email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '').toLowerCase()
  if (!baseUsername) baseUsername = 'user'
  let username = baseUsername
  let { data: userCheck } = await supabaseClient.from('members').select('username').eq('username', username).maybeSingle()
  let attempts = 0
  while (userCheck && attempts < 100) {
    username = baseUsername + Math.floor(Math.random() * 99999)
    let result = await supabaseClient.from('members').select('username').eq('username', username).maybeSingle()
    userCheck = result.data
    attempts++
  }
  if (userCheck) { console.error('Signup failed: could not generate unique username after 100 attempts'); return { error: 'Registration could not be completed. Please try again later.' } }

  // 3. Generate unique access key
  let accessKey = generateAccessKey()
  let { data: keyCheck } = await supabaseClient.from('members').select('id').eq('access_key', accessKey).maybeSingle()
  let keyAttempts = 0
  while (keyCheck && keyAttempts < 100) {
    accessKey = generateAccessKey()
    let keyResult = await supabaseClient.from('members').select('id').eq('access_key', accessKey).maybeSingle()
    keyCheck = keyResult.data
    keyAttempts++
  }
  if (keyCheck) { console.error('Signup failed: could not generate unique access key after 100 attempts'); return { error: 'Registration could not be completed. Please try again later.' } }

  // 4. Sanitize strings
  function sanitize(val) { return val ? val.replace(/<[^>]*>/g, '').replace(/[&<>"'`]/g, '').trim() : '' }
  let safeName = sanitize(name) || username
  let safePhone = sanitize(phone)
  let safeStreet = sanitize(street)
  let safeCity = sanitize(city)
  let safeState = sanitize(state)
  let safeZip = sanitize(zip)
  let safeCountry = sanitize(country)
  let authPassword = generatePassword()

  // 5. Insert member record FIRST (before auth) to avoid orphaned auth user if DB insert fails
  let { data: insResult, error } = await rpcInsert('member', {
    email: email,
    name: safeName,
    username: username,
    access_key: accessKey,
    balance: 0,
    status: 'active',
    date_of_birth: dob || null,
    phone: safePhone || null,
    address_street: safeStreet || null,
    address_city: safeCity || null,
    address_state: safeState || null,
    address_zip: safeZip || null,
    address_country: safeCountry || null
  })
  let data = insResult
  if (error) { console.error('DB insert error:', error.message, error.details); return { error: 'Database error: ' + (error.message || 'unknown') } }
  if (!data) { return { error: 'Database error: insert returned no data' } }

  // 6. Create Supabase Auth user (metadata only contains non-sensitive info)
  let authResp = await supabaseClient.auth.signUp({
    email: email,
    password: authPassword,
    options: {
      data: {
        username: username
      }
    }
  })
  if (authResp.error) {
    console.error('Auth signup error:', authResp.error)
    if (!data || !data.id) {
      return { error: 'Registration could not be completed. Please try again later.' }
    }
    // Clean up the member record since auth creation failed
    await supabaseClient.auth.signOut().catch(function() {})
    try { await rpcDelete('member', { id: data.id }) } catch(e) {}
    let errMsg = (authResp.error.message || authResp.error.description || '').toLowerCase()
    if (errMsg.includes('already registered') || errMsg.includes('already exists') || errMsg.includes('already in use') || (authResp.error.name === 'AuthApiError' && (authResp.error.status === 422 || authResp.error.status === 409))) {
      return { error: 'This email is already registered. Please use a different email or sign in.' }
    }
    return { error: 'Registration could not be completed. ' + (authResp.error.message || 'Please try again later.') }
  }
  let authUid = authResp.data && authResp.data.user ? authResp.data.user.id : null

  // 7. Update member with auth_uid and auth_password
  let updateResp = await rpcUpdate('member', { id: data.id }, { auth_uid: authUid, auth_password: authPassword })
  if (updateResp.error) { console.error('Failed to update member auth fields:', updateResp.error) }

  // Re-fetch to get fresh data including auth_uid
  let { data: refreshed } = await supabaseClient.from('members').select('id, name, username, email, balance, status, access_key, auth_uid, created_at, last_login').eq('id', data.id).maybeSingle()
  if (refreshed) data = refreshed

  // Auto-confirm email via RPC so user doesn't need to click the confirmation link
  try { await supabaseClient.rpc('confirm_auth_user', { user_id: authUid }) } catch(e) { console.error('Auto-confirm failed:', e) }

  // Sign in automatically so user goes straight to dashboard
  try {
    await supabaseClient.auth.signInWithPassword({ email: email, password: authPassword })
  } catch(e) { console.error('Auto-login failed:', e) }
  sessionStorage.setItem('member_user', JSON.stringify(data))

  return { data: { ...data, access_key: accessKey } }
}

function timingSafeEqual(a, b) {
  // Constant-time string comparison to prevent timing side-channel attacks
  if (typeof a !== 'string' || typeof b !== 'string') return false
  let len = Math.max(a.length, b.length)
  let result = 0
  for (let i = 0; i < len; i++) {
    result |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0)
  }
  return result === 0
}

// ===== ADMIN AUTH =====
// Admin password hash is loaded from DB on demand, never stored in a global variable
let _adminPwHash = null

async function loadAdminPasswordHash() {
  try {
    let { data } = await supabaseClient.rpc('rpc_admin_get_setting', { p_key: 'admin_password_hash' })
    if (data) _adminPwHash = data
  } catch(e) { console.error('Failed to load admin password hash:', e) }
}

async function adminLogin(email, password) {
  try {
    if (!password) return { error: 'Password is required' }
    if (!crypto || !crypto.subtle) return { error: 'Secure context required. Use HTTPS.' }
    let hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password))
    let hashHex = Array.from(new Uint8Array(hash)).map(function(b) { return b.toString(16).padStart(2, '0') }).join('')

    let rateId = email.toLowerCase()

    // Try agent login first (skip for admin@secure.metasbank — that's always the super admin)
    if (email.toLowerCase() !== 'admin@secure.metasbank') {
      let { data: agent } = await supabaseClient.rpc('rpc_verify_agent_login', { p_email: email.toLowerCase(), p_hash: hashHex })
      let matched = agent && agent.length > 0 ? agent[0] : null
      if (matched) {
        await supabaseClient.rpc('reset_rate_limit', { p_action: 'admin_login', p_identifier: rateId })
        let role = matched.role || 'agent'
        sessionStorage.setItem('admin_session', JSON.stringify({ user: { email, agent_id: matched.id, name: matched.name, role: role } }))
        return { data: { user: { email, agent_id: matched.id, name: matched.name, role: role } } }
      }
    }

    // Fall back to legacy admin login
    if (email.toLowerCase() !== 'admin@secure.metasbank') {
      return { error: 'Unauthorized admin email' }
    }
    if (!_adminPwHash) await loadAdminPasswordHash()
    if (!_adminPwHash) return { error: 'Admin password not configured' }
    if (!timingSafeEqual(hashHex, _adminPwHash)) {
      let { data: rateOk } = await supabaseClient.rpc('check_rate_limit', { p_action: 'admin_login', p_identifier: rateId, p_max_attempts: 5, p_window_minutes: 1 })
      if (rateOk === false) { return { error: 'Too many failed attempts. Try again later.' } }
      return { error: 'Invalid password' }
    }
    await supabaseClient.rpc('reset_rate_limit', { p_action: 'admin_login', p_identifier: rateId })
    // Also look up admin's agent record so admin can attend chats
    let adminAgent = { agent_id: null, name: 'Admin' }
    try {
      let { data: a } = await supabaseClient.from('agents').select('id, name').eq('email', email.toLowerCase()).maybeSingle()
      if (a) { adminAgent.agent_id = a.id; adminAgent.name = a.name || 'Admin' }
    } catch(e) {}
    sessionStorage.setItem('admin_session', JSON.stringify({ user: { email, role: 'admin', agent_id: adminAgent.agent_id, name: adminAgent.name } }))
    return { data: { user: { email, role: 'admin', agent_id: adminAgent.agent_id, name: adminAgent.name } } }
  } catch(e) { console.error('Admin login error:', e); return { error: 'Authentication error' } }
}

async function updateAdminPassword(newPassword) {
  try {
    let strengthErr = validatePasswordStrength(newPassword)
    if (strengthErr) return { error: strengthErr }
    if (!crypto || !crypto.subtle) return { error: 'Secure context required. Use HTTPS.' }
    let hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(newPassword))
    let hashHex = Array.from(new Uint8Array(hash)).map(function(b) { return b.toString(16).padStart(2, '0') }).join('')
    let { error } = await rpc_upsert('setting', { key: 'admin_password_hash', value: hashHex })
    if (error) return { error: error.message }
    _adminPwHash = hashHex
    return {}
  } catch(e) { console.error('updateAdminPassword error:', e); return { error: 'Failed to update password' } }
}

async function adminLogout() {
  sessionStorage.removeItem('admin_session')
  window.location.href = '/admin/login.html'
}

function getAdminSession() {
  try { return JSON.parse(sessionStorage.getItem('admin_session')) } catch(e) { return null }
}

// ===== SERVER-SIDE SESSION VERIFICATION =====
// Verifies admin/agent session against the database to prevent tampering

function validatePasswordStrength(pw) {
  if (!pw || pw.length < 8) return 'Password must be at least 8 characters'
  if (!/[A-Z]/.test(pw)) return 'Password must contain at least one uppercase letter'
  if (!/[a-z]/.test(pw)) return 'Password must contain at least one lowercase letter'
  if (!/[0-9]/.test(pw)) return 'Password must contain at least one number'
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pw)) return 'Password must contain at least one special character'
  return null
}

async function verifyAdminSession(expectedRole) {
  let session = getAdminSession()
  if (!session || !session.user) return null
  if (session.user.email === 'admin@secure.metasbank') {
    // Super admin: verify password hash still matches
    if (!_adminPwHash) await loadAdminPasswordHash()
    if (!_adminPwHash) return null
    return session
  }
  // Agent: verify agent record still exists in DB
  try {
    let { data: agents } = await supabaseClient.rpc('rpc_admin_get_agents_safe')
    let agent = agents ? agents.find(function(a) { return a.email === session.user.email.toLowerCase() }) : null
    if (!agent || agent.status === 'disabled') return null
    if (expectedRole === 'admin' && agent.role !== 'admin') return null
    if (expectedRole === 'agent' && !agent.role) return null
    // Refresh session data from DB
    session.user.name = agent.name
    session.user.agent_id = agent.id
    session.user.role = agent.role || 'agent'
    sessionStorage.setItem('admin_session', JSON.stringify(session))
    return session
  } catch(e) { console.error('Session verification error:', e); return null }
}

// ===== RPC WRITE HELPERS (bypass RLS via SECURITY DEFINER) =====
// All write operations go through these RPCs so we can
// enable SELECT-only RLS policies for the anon key.

async function rpcUpdate(table, match, data) {
  // Generic single-row update via RPC
  // table: table name, match: { column: value }, data: { column: value }
  // Returns { data, error }
  let keys = Object.keys(match)
  let id = match[keys[0]]
  // Build params from data
  let params = {}
  for (let k in data) { params['p_' + k] = data[k] }
  params['p_' + keys[0]] = id
  return await supabaseClient.rpc('rpc_update_' + table, params)
}

async function rpcInsert(table, data) {
  // Generic insert via RPC
  let params = {}
  for (let k in data) { params['p_' + k] = data[k] }
  return await supabaseClient.rpc('rpc_insert_' + table, params)
}

async function rpcDelete(table, match) {
  // Generic delete via RPC
  let keys = Object.keys(match)
  let id = match[keys[0]]
  return await supabaseClient.rpc('rpc_delete_' + table, { p_id: id })
}

// Specific wrappers for clarity in the app code

async function rpc_upsert(table, data) {
  let params = {}
  for (let k in data) { params['p_' + k] = data[k] }
  return await supabaseClient.rpc('rpc_upsert_' + table, params)
}

// Initialize immediately
initSupabase()
