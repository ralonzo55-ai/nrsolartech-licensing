// N&R SOLARTECH - Secure API
// service_role key is in Vercel environment variables - NEVER exposed to browser

const SB_URL = process.env.SUPABASE_URL || 'https://sdviemivuftnsytmnqaq.supabase.co';
const SB_ANON = process.env.SUPABASE_ANON_KEY || '';
const SB_SECRET = process.env.SUPABASE_SERVICE_KEY || '';

async function db(table, method, options = {}) {
  if (!SB_SECRET) throw new Error('SUPABASE_SERVICE_KEY env variable is missing in Vercel');
  let url = `${SB_URL}/rest/v1/${table}`;
  const headers = {
    'apikey': SB_SECRET,
    'Authorization': `Bearer ${SB_SECRET}`,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  };
  if (method === 'POST') headers['Prefer'] = 'return=representation';
  else if (method === 'PATCH' || method === 'DELETE') headers['Prefer'] = 'return=minimal';
  if (options.query) url += `?${options.query}`;
  const opts = { method: method || 'GET', headers };
  if (options.body) opts.body = JSON.stringify(options.body);
  const res = await fetch(url, opts);
  if (!res.ok) { const t = await res.text(); throw new Error(`DB ${res.status}: ${t}`); }
  const ct = res.headers.get('content-type');
  if (ct && ct.includes('json')) return res.json();
  return null;
}

async function log(a, k, c, d) {
  try { await db('logs', 'POST', { body: { action: a, license_key: k || null, chip_id: c || null, details: d || '' } }); } catch (e) {}
}

function genKey() {
  const c = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const s = () => Array.from({ length: 4 }, () => c[Math.floor(Math.random() * c.length)]).join('');
  return `NR-${s()}-${s()}-${s()}`;
}

// Simple hash for passwords (not bcrypt but much better than plain text)
function hashPw(pw) {
  let h = 0;
  const salt = 'NR$0LAR#2025!';
  const s = salt + pw + salt;
  for (let i = 0; i < s.length; i++) { h = ((h << 5) - h + s.charCodeAt(i)) | 0; }
  return 'h1_' + Math.abs(h).toString(36) + '_' + s.length;
}

// Telegram notification helper
async function sendTelegram(message) {
  try {
    const settings = await db('site_settings', 'GET', { query: 'id=eq.1&select=telegram_bot_token,telegram_chat_id,telegram_notify' });
    const s = settings && settings[0] ? settings[0] : {};
    if (!s.telegram_notify || !s.telegram_bot_token || !s.telegram_chat_id) return;
    const url = `https://api.telegram.org/bot${s.telegram_bot_token}/sendMessage`;
    await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id: s.telegram_chat_id, text: message, parse_mode: 'HTML' }) });
  } catch (e) { /* silent fail - notification is not critical */ }
}

// Rate limiter (in-memory, resets on cold start - acceptable for rate limiting)
const attempts = {};
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  if (!attempts[key]) attempts[key] = [];
  attempts[key] = attempts[key].filter(t => now - t < windowMs);
  if (attempts[key].length >= max) return false;
  attempts[key].push(now);
  return true;
}

// Session tokens - stored in DATABASE (persists across cold starts)
async function createSession(userId, type) {
  const token = Array.from({ length: 48 }, () => 'abcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random() * 36)]).join('');
  // Delete old sessions for this user (keep only latest)
  try { await db('sessions', 'DELETE', { query: `user_id=eq.${userId}` }); } catch(e) {}
  await db('sessions', 'POST', { body: { token, user_id: userId, user_type: type } });
  return token;
}
async function getSession(token) {
  if (!token) return null;
  try {
    const s = await db('sessions', 'GET', { query: `token=eq.${encodeURIComponent(token)}&select=*` });
    if (!s || !s.length) return null;
    // Check if session is older than 10 minutes of inactivity
    const age = Date.now() - new Date(s[0].created_at).getTime();
    if (age > 10 * 60000) {
      try { await db('sessions', 'DELETE', { query: `token=eq.${encodeURIComponent(token)}` }); } catch(e) {}
      return null;
    }
    // Refresh session timestamp on every use (keep alive while active)
    try { await db('sessions', 'PATCH', { query: `token=eq.${encodeURIComponent(token)}`, body: { created_at: new Date().toISOString() } }); } catch(e) {}
    return { userId: s[0].user_id, type: s[0].user_type };
  } catch(e) { return null; }
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || '';
  const authToken = (req.headers.authorization || '').replace('Bearer ', '');

  // === GLOBAL PROTECTION ===
  // Global rate limit per IP: 120 requests per minute
  if (!rateLimit('global_' + ip, 120, 60000)) return res.status(429).json({ error: 'Too many requests. Slow down.' });
  // Body size check - reject oversized payloads
  const bodyStr = JSON.stringify(req.body || {});
  if (bodyStr.length > 50000) return res.status(413).json({ error: 'Payload too large' });

  try {
    const body = req.body || {};
    const { action } = body;

    // Block invalid/empty actions early
    if (!action && !body.update_id) return res.status(400).json({ error: 'Invalid request' });

    // ==================== TELEGRAM BOT WEBHOOK ====================
    if (body.update_id && body.message) {
      if (!rateLimit('tg_' + ip, 30, 60000)) return res.status(200).json({ ok: true });
      // This is a Telegram webhook update
      const msg = body.message;
      const text = (msg.text || '').trim();
      const chatId = msg.chat.id;
      
      // Verify this is from our admin chat
      const settings = await db('site_settings', 'GET', { query: 'id=eq.1&select=telegram_bot_token,telegram_chat_id' });
      const s = settings && settings[0] ? settings[0] : {};
      if (!s.telegram_bot_token || String(chatId) !== String(s.telegram_chat_id)) return res.status(200).json({ ok: true });
      
      const botUrl = `https://api.telegram.org/bot${s.telegram_bot_token}/sendMessage`;
      const reply = async (txt) => { try { await fetch(botUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id: chatId, text: txt, parse_mode: 'HTML' }) }); } catch(e){} };
      
      if (text.toLowerCase().startsWith('/approve ')) {
        const ref = text.substring(9).trim();
        if (!ref) { await reply('❌ Usage: /approve <reference number>'); return res.status(200).json({ ok: true }); }
        const pays = await db('pending_payments', 'GET', { query: `ref_number=eq.${encodeURIComponent(ref)}&status=eq.pending&select=*` });
        if (!pays || !pays.length) { await reply('❌ No pending payment found with ref: ' + ref); return res.status(200).json({ ok: true }); }
        const p = pays[0];
        await db('pending_payments', 'PATCH', { query: `id=eq.${p.id}`, body: { status: 'approved' } });
        // Generate license keys (bulk support)
        const qty = p.quantity || 1;
        const keys = [];
        for (let i = 0; i < qty; i++) { const k = genKey(); await db('licenses', 'POST', { body: { key: k, type: 'permanent', status: 'inactive', customer_id: p.customer_id } }); keys.push(k); }
        await log('payment_approved', keys[0], null, 'Telegram: ' + p.customer_name + ' ref:' + ref + ' x' + qty);
        await reply('✅ <b>APPROVED!</b>\n\n👤 ' + p.customer_name + '\n📝 Ref: <code>' + ref + '</code>\n💵 ₱' + p.amount + (qty > 1 ? ' (' + qty + ' licenses)' : '') + '\n\n' + keys.map(function(k) { return '🔑 <code>' + k + '</code>'; }).join('\n') + '\n\nAssigned to customer account.');
        return res.status(200).json({ ok: true });
      }
      
      if (text.toLowerCase().startsWith('/reject ')) {
        const ref = text.substring(8).trim();
        if (!ref) { await reply('❌ Usage: /reject <reference number>'); return res.status(200).json({ ok: true }); }
        const pays = await db('pending_payments', 'GET', { query: `ref_number=eq.${encodeURIComponent(ref)}&status=eq.pending&select=*` });
        if (!pays || !pays.length) { await reply('❌ No pending payment found with ref: ' + ref); return res.status(200).json({ ok: true }); }
        const p = pays[0];
        await db('pending_payments', 'PATCH', { query: `id=eq.${p.id}`, body: { status: 'rejected' } });
        await log('payment_rejected', null, null, 'Telegram: ' + p.customer_name + ' ref:' + ref);
        await reply('❌ <b>Rejected</b>\n\n👤 ' + p.customer_name + '\n📝 Ref: ' + ref);
        return res.status(200).json({ ok: true });
      }
      
      if (text.toLowerCase() === '/pending') {
        const pays = await db('pending_payments', 'GET', { query: 'status=eq.pending&select=*&order=submitted_at.desc&limit=10' });
        if (!pays || !pays.length) { await reply('✅ No pending payments'); return res.status(200).json({ ok: true }); }
        let msg = '📋 <b>Pending Payments (' + pays.length + ')</b>\n\n';
        pays.forEach(function(p) { msg += '👤 ' + p.customer_name + '\n💳 ' + p.method + ' | ₱' + p.amount + '\n📝 Ref: <code>' + (p.ref_number || 'N/A') + '</code>\n\n'; });
        msg += 'Reply with:\n/approve [ref]\n/reject [ref]';
        await reply(msg);
        return res.status(200).json({ ok: true });
      }
      
      if (text.toLowerCase() === '/help') {
        await reply('🤖 <b>N&R SOLARTECH Bot</b>\n\n/pending — View pending payments\n/approve [ref] — Approve payment\n/reject [ref] — Reject payment\n/stats — Quick stats\n/help — Show this help');
        return res.status(200).json({ ok: true });
      }
      
      if (text.toLowerCase() === '/stats') {
        const [lics, custs, devs] = await Promise.all([
          db('licenses', 'GET', { query: 'select=status' }),
          db('customers', 'GET', { query: 'select=id' }),
          db('devices', 'GET', { query: 'select=id' })
        ]);
        const active = (lics||[]).filter(l => l.status === 'active').length;
        await reply('📊 <b>Stats</b>\n\n🔑 Licenses: ' + (lics||[]).length + ' (' + active + ' active)\n👥 Customers: ' + (custs||[]).length + '\n📱 Devices: ' + (devs||[]).length);
        return res.status(200).json({ ok: true });
      }
      
      return res.status(200).json({ ok: true });
    }

    // ==================== AUTH: Register ====================
    if (action === 'register') {
      if (!body.name || !body.email || !body.password || !body.secret) return res.status(400).json({ error: 'All fields required including secret number' });
      if (body.name.length > 50 || body.email.length > 100 || body.password.length > 100) return res.status(400).json({ error: 'Input too long' });
      if (body.password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });
      if (body.secret.length < 4 || body.secret.length > 6) return res.status(400).json({ error: 'Secret number must be 4-6 digits' });
      if (!rateLimit('reg_' + ip, 5, 3600000)) return res.status(429).json({ error: 'Too many registrations. Try again later.' });
      const ex = await db('customers', 'GET', { query: `email=eq.${encodeURIComponent(body.email)}&select=id` });
      if (ex && ex.length) return res.status(409).json({ error: 'Email already registered' });
      const r = await db('customers', 'POST', { body: { name: body.name.trim(), phone: body.phone || '', email: body.email.trim().toLowerCase(), password_hash: hashPw(body.password), secret_number: body.secret } });
      const token = await createSession(r[0].id, 'c');
      await log('register', null, null, body.name.trim() + ' registered (' + body.email.trim() + ')');
      return res.status(200).json({ success: true, customer: { id: r[0].id, name: r[0].name, email: r[0].email, phone: r[0].phone }, token });
    }

    // ==================== AUTH: Customer Login ====================
    if (action === 'login') {
      if (!rateLimit('login_' + ip, 10, 600000)) return res.status(429).json({ error: 'Too many login attempts. Wait 10 minutes.' });
      const email = (body.email || '').trim().toLowerCase();
      const password = body.password || '';
      if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
      const custs = await db('customers', 'GET', { query: `email=eq.${encodeURIComponent(email)}&select=*` });
      if (!custs || !custs.length) return res.status(401).json({ error: 'Invalid email or password' });
      const c = custs[0];
      const hashed = hashPw(password);
      // Check: hashed password match OR plain text match
      if (c.password_hash !== hashed && c.password_hash !== password) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }
      // Auto-upgrade plain text to hashed
      if (c.password_hash === password && c.password_hash !== hashed) {
        try { await db('customers', 'PATCH', { query: `id=eq.${c.id}`, body: { password_hash: hashed } }); } catch (e) {}
      }
      const token = await createSession(c.id, 'c');
      await log('login', null, null, c.name + ' logged in');
      return res.status(200).json({ success: true, customer: { id: c.id, name: c.name, email: c.email, phone: c.phone }, token });
    }

    // ==================== AUTH: Admin Login ====================
    if (action === 'admin_login') {
      if (!rateLimit('admin_' + ip, 5, 600000)) return res.status(429).json({ error: 'Too many attempts. Wait 10 minutes.' });
      const admins = await db('admins', 'GET', { query: `email=eq.${encodeURIComponent((body.email || '').trim().toLowerCase())}&select=*` });
      if (!admins || !admins.length) return res.status(401).json({ error: 'Invalid credentials' });
      const a = admins[0];
      if (a.password_hash !== hashPw(body.password) && a.password_hash !== body.password) return res.status(401).json({ error: 'Invalid credentials' });
      if (a.password_hash === body.password) { try { await db('admins', 'PATCH', { query: `id=eq.${a.id}`, body: { password_hash: hashPw(body.password) } }); } catch (e) {} }
      const token = await createSession(a.id, 'a');
      return res.status(200).json({ success: true, admin: { email: a.email, backup_email: a.backup_email||'', secret_number: a.secret_number||'' }, token });
    }

    // ==================== FORGOT PASSWORD (no auth needed) ====================
    if (action === 'forgot_password') {
      if (!body.email || !body.secret) return res.status(400).json({ error: 'Email and secret number required' });
      if (!rateLimit('forgot_' + ip, 5, 600000)) return res.status(429).json({ error: 'Too many attempts. Wait 10 minutes.' });
      const custs = await db('customers', 'GET', { query: `email=eq.${encodeURIComponent((body.email||'').trim().toLowerCase())}&select=*` });
      if (!custs || !custs.length) return res.status(404).json({ error: 'Email not found' });
      const c = custs[0];
      if (c.secret_number !== body.secret) return res.status(403).json({ error: 'Wrong secret number' });
      // Reset to default password
      const defaultPw = '123456789';
      await db('customers', 'PATCH', { query: `id=eq.${c.id}`, body: { password_hash: hashPw(defaultPw) } });
      await log('password_reset', null, null, 'Customer reset via secret: ' + c.email);
      return res.status(200).json({ success: true, message: 'Password reset to: 123456789. Please login and change it.' });
    }

    // ==================== ADMIN FORGOT (no auth needed) ====================
    if (action === 'admin_forgot') {
      if (!body.backupEmail || !body.secret) return res.status(400).json({ error: 'Backup email and secret number required' });
      if (!rateLimit('adminforgot_' + ip, 3, 600000)) return res.status(429).json({ error: 'Too many attempts. Wait 10 minutes.' });
      const admins = await db('admins', 'GET', { query: `backup_email=eq.${encodeURIComponent((body.backupEmail||'').trim().toLowerCase())}&select=*` });
      if (!admins || !admins.length) return res.status(404).json({ error: 'Backup email not found' });
      const a = admins[0];
      if (a.secret_number !== body.secret) return res.status(403).json({ error: 'Wrong secret number' });
      // Reset password and return login email
      const defaultPw = '123456789';
      await db('admins', 'PATCH', { query: `id=eq.${a.id}`, body: { password_hash: hashPw(defaultPw) } });
      await log('admin_reset', null, null, 'Admin password reset via backup email');
      return res.status(200).json({ success: true, loginEmail: a.email, message: 'Password reset to 123456789' });
    }

    // ==================== ESP32: Activate ====================
    if (action === 'track_download') {
      if (!rateLimit('dl_' + ip, 10, 60000)) return res.status(200).json({ ok: true });
      const file = body.file || '';
      if (file) {
        try {
          const prods = await db('products', 'GET', { query: `firmware_file=eq.${encodeURIComponent(file)}&select=id,download_count` });
          if (prods && prods[0]) {
            await db('products', 'PATCH', { query: `id=eq.${prods[0].id}`, body: { download_count: (prods[0].download_count || 0) + 1 } });
          }
        } catch(e){}
      }
      return res.status(200).json({ ok: true });
    }

    if (action === 'activate_device') {
      const { key, chipId, firmware } = body;
      if (!key || !chipId) return res.status(400).json({ status: 'error', message: 'Missing key or chipId' });
      if (!rateLimit('act_' + chipId, 10, 600000)) return res.status(429).json({ status: 'error', message: 'Rate limited' });
      const lics = await db('licenses', 'GET', { query: `key=eq.${encodeURIComponent(key)}&select=*` });
      if (!lics || !lics.length) { await log('activate_failed', key, chipId, 'Invalid key'); return res.status(404).json({ status: 'error', message: 'Invalid license key' }); }
      const l = lics[0];
      if (l.status === 'revoked') return res.status(403).json({ status: 'error', message: 'License revoked' });
      if (l.status === 'suspended') return res.status(403).json({ status: 'error', message: 'License suspended' });
      if (l.status === 'active' && l.chip_id && l.chip_id !== chipId) return res.status(409).json({ status: 'error', message: 'License active on another device' });
      if (l.status === 'active' && l.chip_id === chipId) return res.status(200).json({ status: 'active', message: 'Already activated' });
      await db('licenses', 'PATCH', { query: `key=eq.${encodeURIComponent(key)}`, body: { status: 'active', chip_id: chipId, activated_at: new Date().toISOString() } });
      try {
        const devs = await db('devices', 'GET', { query: `chip_id=eq.${encodeURIComponent(chipId)}&select=id` });
        if (devs && devs.length) await db('devices', 'PATCH', { query: `chip_id=eq.${encodeURIComponent(chipId)}`, body: { firmware_version: firmware || '', last_seen: new Date().toISOString(), ip_address: ip, license_key: key } });
        else await db('devices', 'POST', { body: { chip_id: chipId, firmware_version: firmware || '', last_seen: new Date().toISOString(), ip_address: ip, license_key: key } });
      } catch (e) {}
      await log('activate', key, chipId, 'Activated');
      return res.status(200).json({ status: 'active', message: 'License activated!' });
    }

    // ==================== ESP32: Verify ====================
    if (action === 'verify_device') {
      if (!rateLimit('verify_' + ip, 30, 60000)) return res.status(429).json({ status: 'error', message: 'Rate limited' });
      const { key, chipId, firmware, deviceStatus, failCount, wifiRSSI } = body;
      if (!key || !chipId) return res.status(400).json({ status: 'error', message: 'Missing' });
      const lics = await db('licenses', 'GET', { query: `key=eq.${encodeURIComponent(key)}&select=*` });
      if (!lics || !lics.length) return res.status(404).json({ status: 'invalid' });
      const l = lics[0];
      // Update device with status info from ESP32
      try { await db('devices', 'PATCH', { query: `chip_id=eq.${encodeURIComponent(chipId)}`, body: { last_seen: new Date().toISOString(), ip_address: ip, firmware_version: firmware || '', device_status: deviceStatus || 'unknown', wifi_rssi: wifiRSSI || 0 } }); } catch (e) {}
      if (l.status === 'active' && l.chip_id === chipId) return res.status(200).json({ status: 'active', verify: 'ok' });
      if (l.status === 'suspended') return res.status(403).json({ status: 'suspended', verify: 'fail' });
      if (l.status === 'revoked') return res.status(403).json({ status: 'revoked', verify: 'fail' });
      return res.status(403).json({ status: 'inactive', verify: 'fail' });
    }

    // ==================== AUTHENTICATED ROUTES ====================
    const session = await getSession(authToken);
    if (!session) return res.status(401).json({ error: 'Not authenticated. Please login again.' });

    // ---------- CUSTOMER ROUTES ----------
    if (session.type === 'c') {
      const uid = session.userId;

      if (action === 'my_licenses') {
        const lics = await db('licenses', 'GET', { query: `customer_id=eq.${uid}&select=*` });
        return res.status(200).json({ licenses: lics || [] });
      }
      if (action === 'my_logs') {
        const custs = await db('customers', 'GET', { query: `id=eq.${uid}&select=name,email` });
        const me = custs && custs[0] ? custs[0] : {};
        const lics = await db('licenses', 'GET', { query: `customer_id=eq.${uid}&select=key` });
        const keys = (lics || []).map(l => l.key);
        let all = [];
        // Single query for all license keys using or filter
        if (keys.length) {
          const keyFilter = keys.map(k => 'license_key.eq.' + encodeURIComponent(k)).join(',');
          try { const logs = await db('logs', 'GET', { query: `or=(${keyFilter})&select=*&order=timestamp.desc&limit=50` }); if (logs) all = logs; } catch(e){}
        }
        // Logs mentioning customer name
        if (me.name) { try { const nameLogs = await db('logs', 'GET', { query: `details=ilike.*${encodeURIComponent(me.name)}*&select=*&order=timestamp.desc&limit=30` }); if (nameLogs) all = all.concat(nameLogs); } catch(e){} }
        // Deduplicate by id
        const seen = {};
        all = all.filter(function(l) { if (seen[l.id]) return false; seen[l.id] = true; return true; });
        all.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        return res.status(200).json({ logs: all.slice(0, 50) });
      }
      if (action === 'claim') {
        const key = (body.key || '').toUpperCase().trim();
        if (!key) return res.status(400).json({ error: 'Enter a key' });
        const lics = await db('licenses', 'GET', { query: `key=eq.${encodeURIComponent(key)}&select=*` });
        if (!lics || !lics.length) return res.status(404).json({ error: 'Invalid key' });
        const l = lics[0];
        if (l.customer_id && l.customer_id !== uid) return res.status(403).json({ error: 'Belongs to another customer' });
        if (l.customer_id === uid) return res.status(400).json({ error: 'Already yours' });
        await db('licenses', 'PATCH', { query: `key=eq.${encodeURIComponent(key)}`, body: { customer_id: uid } });
        await log('claimed', key, null, 'Customer claimed');
        return res.status(200).json({ success: true });
      }
      if (action === 'transfer') {
        // Device transfer (deactivate from current device for re-activation)
        if (!body.password || !body.email) return res.status(400).json({ error: 'Email and password required' });
        const custs = await db('customers', 'GET', { query: `id=eq.${uid}&select=*` });
        if (!custs || !custs.length) return res.status(404).json({ error: 'Not found' });
        const me = custs[0];
        if (me.password_hash !== hashPw(body.password) && me.password_hash !== body.password) return res.status(403).json({ error: 'Wrong password' });
        if (me.email !== body.email.trim().toLowerCase()) return res.status(403).json({ error: 'Email does not match your account' });
        const lics = await db('licenses', 'GET', { query: `key=eq.${encodeURIComponent(body.key)}&select=*` });
        if (!lics || !lics.length) return res.status(404).json({ error: 'License not found' });
        const l = lics[0];
        if (l.customer_id !== uid) return res.status(403).json({ error: 'Not your license' });
        if (!body.confirmChipId || body.confirmChipId.toUpperCase().trim() !== (l.chip_id || '').toUpperCase().trim()) return res.status(403).json({ error: 'Chip ID does not match' });
        await db('licenses', 'PATCH', { query: `key=eq.${encodeURIComponent(body.key)}`, body: { status: 'inactive', chip_id: null, activated_at: null, transfer_count: l.transfer_count + 1 } });
        try { await db('devices', 'DELETE', { query: `license_key=eq.${encodeURIComponent(body.key)}` }); } catch(e) {}
        try { if (l.chip_id) await db('devices', 'DELETE', { query: `chip_id=eq.${encodeURIComponent(l.chip_id)}` }); } catch (e) {}
        await log('transfer_device', body.key, l.chip_id, me.name + ' deactivated from device (Transfer #' + (l.transfer_count + 1) + ')');
        return res.status(200).json({ success: true });
      }
      if (action === 'transfer_account') {
        // Transfer license to another registered customer
        if (!body.password || !body.email) return res.status(400).json({ error: 'Your email and password required' });
        if (!body.recipientEmail) return res.status(400).json({ error: 'Recipient email required' });
        const custs = await db('customers', 'GET', { query: `id=eq.${uid}&select=*` });
        if (!custs || !custs.length) return res.status(404).json({ error: 'Not found' });
        const me = custs[0];
        if (me.password_hash !== hashPw(body.password) && me.password_hash !== body.password) return res.status(403).json({ error: 'Wrong password' });
        if (me.email !== body.email.trim().toLowerCase()) return res.status(403).json({ error: 'Email does not match your account' });
        const recip = await db('customers', 'GET', { query: `email=eq.${encodeURIComponent(body.recipientEmail.trim().toLowerCase())}&select=id,name,email` });
        if (!recip || !recip.length) return res.status(404).json({ error: 'Recipient email not registered on our platform' });
        const recipient = recip[0];
        if (recipient.id === uid) return res.status(400).json({ error: 'Cannot transfer to yourself' });
        const lics = await db('licenses', 'GET', { query: `key=eq.${encodeURIComponent(body.key)}&select=*` });
        if (!lics || !lics.length) return res.status(404).json({ error: 'License not found' });
        const l = lics[0];
        if (l.customer_id !== uid) return res.status(403).json({ error: 'Not your license' });
        // Deactivate device if active
        try { await db('devices', 'DELETE', { query: `license_key=eq.${encodeURIComponent(body.key)}` }); } catch(e) {}
        if (l.chip_id) { try { await db('devices', 'DELETE', { query: `chip_id=eq.${encodeURIComponent(l.chip_id)}` }); } catch(e){} }
        // Transfer to new owner with sender info
        await db('licenses', 'PATCH', { query: `key=eq.${encodeURIComponent(body.key)}`, body: { status: 'inactive', chip_id: null, activated_at: null, customer_id: recipient.id, transfer_count: l.transfer_count + 1, transferred_from: me.email, transferred_from_name: me.name, transferred_at: new Date().toISOString() } });
        await log('transfer_account', body.key, null, me.name + ' (' + me.email + ') → ' + recipient.name + ' (' + recipient.email + ') Transfer #' + (l.transfer_count + 1));
        return res.status(200).json({ success: true, recipientName: recipient.name });
      }
      if (action === 'submit_payment') {
        if (!rateLimit('pay_' + uid, 3, 3600000)) return res.status(429).json({ error: 'Too many submissions. Wait 1 hour.' });
        const custs = await db('customers', 'GET', { query: `id=eq.${uid}&select=name` });
        const name = custs && custs[0] ? custs[0].name : 'Unknown';
        const qty = body.quantity || 1;
        await db('pending_payments', 'POST', { body: { customer_id: uid, customer_name: name, amount: body.amount || 500, method: body.method || 'GCash', ref_number: (body.refNumber || '').substring(0, 50), proof_url: body.proofUrl || '', quantity: qty } });
        await log('payment_submitted', null, null, name + ' submitted ' + (body.method || 'GCash') + ' payment');
        // Notify admin via Telegram
        sendTelegram(`💰 <b>New Payment!</b>\n\n👤 ${name}\n💳 ${body.method || 'GCash'}\n💵 ₱${body.amount || 500}\n📝 Ref: ${(body.refNumber || 'N/A').substring(0, 50)}`);
        sendTelegram(`/approve ${(body.refNumber || '').substring(0, 50)}`);
        sendTelegram(`/reject ${(body.refNumber || '').substring(0, 50)}`);
        return res.status(200).json({ success: true });
      }
      if (action === 'my_payments') {
        const pays = await db('pending_payments', 'GET', { query: `customer_id=eq.${uid}&select=*&order=submitted_at.desc` });
        return res.status(200).json({ payments: pays || [] });
      }
      if (action === 'change_customer_password') {
        if (!body.oldPassword || !body.newPassword) return res.status(400).json({ error: 'Old and new password required' });
        if (body.newPassword.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });
        const custs = await db('customers', 'GET', { query: `id=eq.${uid}&select=*` });
        if (!custs || !custs.length) return res.status(404).json({ error: 'Not found' });
        const c = custs[0];
        if (c.password_hash !== hashPw(body.oldPassword) && c.password_hash !== body.oldPassword) return res.status(403).json({ error: 'Current password is wrong' });
        await db('customers', 'PATCH', { query: `id=eq.${uid}`, body: { password_hash: hashPw(body.newPassword) } });
        await log('password_changed', null, null, c.name + ' changed password');
        return res.status(200).json({ success: true });
      }
      if (action === 'change_customer_email') {
        if (!body.newEmail || !body.password) return res.status(400).json({ error: 'New email and password required' });
        const custs = await db('customers', 'GET', { query: `id=eq.${uid}&select=*` });
        if (!custs || !custs.length) return res.status(404).json({ error: 'Not found' });
        const c = custs[0];
        if (c.password_hash !== hashPw(body.password) && c.password_hash !== body.password) return res.status(403).json({ error: 'Wrong password' });
        const ex = await db('customers', 'GET', { query: `email=eq.${encodeURIComponent(body.newEmail.trim().toLowerCase())}&select=id` });
        if (ex && ex.length) return res.status(409).json({ error: 'Email already in use' });
        await db('customers', 'PATCH', { query: `id=eq.${uid}`, body: { email: body.newEmail.trim().toLowerCase() } });
        await log('email_changed', null, null, c.name + ' changed email: ' + c.email + ' → ' + body.newEmail.trim());
        return res.status(200).json({ success: true });
      }
    }

    // ---------- ADMIN ROUTES ----------
    if (session.type === 'a') {
      if (action === 'dashboard') {
        const [licenses, customers, devices, logs, payments, settings, pms, dls, products] = await Promise.all([
          db('licenses', 'GET', { query: 'select=*&order=created_at.desc' }),
          db('customers', 'GET', { query: 'select=id,name,email,phone,secret_number,created_at&order=created_at.desc' }),
          db('devices', 'GET', { query: 'select=*&order=last_seen.desc' }),
          db('logs', 'GET', { query: 'select=*&order=timestamp.desc&limit=50' }),
          db('pending_payments', 'GET', { query: 'select=*&order=submitted_at.desc' }),
          db('site_settings', 'GET', { query: 'id=eq.1' }),
          db('payment_methods', 'GET', { query: 'select=*&order=sort_order' }),
          db('downloads', 'GET', { query: 'select=*&order=sort_order' }).catch(() => []),
          db('products', 'GET', { query: 'select=*&order=sort_order' }).catch(() => [])
        ]);
        return res.status(200).json({ licenses, customers, devices, logs, payments, settings: (settings && settings[0]) || {}, pms: pms || [], downloads: dls || [], products: products || [] });
      }
      if (action === 'create_license') {
        const n = Math.min(body.count || 1, 100);
        const keys = [];
        for (let i = 0; i < n; i++) { const k = genKey(); await db('licenses', 'POST', { body: { key: k, type: 'permanent', status: 'inactive' } }); keys.push(k); }
        await log('created', keys[0], null, 'Admin generated ' + n + ' keys');
        return res.status(200).json({ success: true, keys });
      }
      if (action === 'approve_payment') {
        const pays = await db('pending_payments', 'GET', { query: `id=eq.${body.paymentId}&select=*` });
        if (!pays || !pays.length) return res.status(404).json({ error: 'Not found' });
        const p = pays[0];
        await db('pending_payments', 'PATCH', { query: `id=eq.${body.paymentId}`, body: { status: 'approved' } });
        const qty = p.quantity || 1;
        const keys = [];
        for (let i = 0; i < qty; i++) { const k = genKey(); await db('licenses', 'POST', { body: { key: k, type: 'permanent', status: 'inactive', customer_id: p.customer_id } }); keys.push(k); }
        await log('payment_approved', keys[0], null, `${p.method} P${p.amount} ${p.customer_name} x${qty}`);
        sendTelegram(`✅ <b>APPROVED!</b>\n\n👤 ${p.customer_name}\n💳 ${p.method}\n💵 ₱${p.amount}${qty > 1 ? ' (' + qty + ' licenses)' : ''}\n📝 Ref: ${p.ref_number || 'N/A'}\n🔑 ${keys.map(k => '<code>' + k + '</code>').join('\n🔑 ')}`);
        return res.status(200).json({ success: true, keys: keys });
      }
      if (action === 'reject_payment') {
        const pays = await db('pending_payments', 'GET', { query: `id=eq.${body.paymentId}&select=*` });
        const p = pays && pays[0] ? pays[0] : {};
        await db('pending_payments', 'PATCH', { query: `id=eq.${body.paymentId}`, body: { status: 'rejected' } });
        sendTelegram(`❌ <b>REJECTED</b>\n\n👤 ${p.customer_name || 'Unknown'}\n📝 Ref: ${p.ref_number || 'N/A'}`);
        return res.status(200).json({ success: true });
      }
      if (action === 'suspend') { await db('licenses', 'PATCH', { query: `key=eq.${encodeURIComponent(body.key)}`, body: { status: 'suspended' } }); await log('suspended', body.key, null, 'Admin'); return res.status(200).json({ success: true }); }
      if (action === 'admin_revoke') { try { await db('devices', 'DELETE', { query: `license_key=eq.${encodeURIComponent(body.key)}` }); } catch(e) {} await db('licenses', 'PATCH', { query: `key=eq.${encodeURIComponent(body.key)}`, body: { status: 'revoked', chip_id: null } }); await log('revoked', body.key, null, 'Admin'); return res.status(200).json({ success: true }); }
      if (action === 'reactivate') { 
        const lics = await db('licenses', 'GET', { query: `key=eq.${encodeURIComponent(body.key)}&select=*` });
        const l = lics && lics[0] ? lics[0] : {};
        // If device was attached (chip_id exists), restore to active. Otherwise inactive (needs new activation).
        const newStatus = l.chip_id ? 'active' : 'inactive';
        await db('licenses', 'PATCH', { query: `key=eq.${encodeURIComponent(body.key)}`, body: { status: newStatus } }); 
        await log('reactivated', body.key, null, 'Admin → ' + newStatus); 
        return res.status(200).json({ success: true }); 
      }
      if (action === 'delete_license') {
        // Fetch full license info before deleting for detailed log
        const lics = await db('licenses', 'GET', { query: `key=eq.${encodeURIComponent(body.key)}&select=*` });
        const lic = lics && lics[0] ? lics[0] : {};
        const chipId = lic.chip_id || null;
        // Get customer name if assigned
        let custName = 'Unassigned';
        if (lic.customer_id) {
          try { const cu = await db('customers', 'GET', { query: `id=eq.${lic.customer_id}&select=name` }); if (cu && cu[0]) custName = cu[0].name; } catch(e) {}
        }
        // Delete device first (FK constraint)
        try { await db('devices', 'DELETE', { query: `license_key=eq.${encodeURIComponent(body.key)}` }); } catch(e) {}
        if (chipId) { try { await db('devices', 'DELETE', { query: `chip_id=eq.${encodeURIComponent(chipId)}` }); } catch(e) {} }
        await db('licenses', 'DELETE', { query: `key=eq.${encodeURIComponent(body.key)}` });
        const details = `Admin deleted | Status was: ${lic.status || 'unknown'} | Customer: ${custName}${chipId ? ' | Device: ' + chipId : ''}`;
        await log('deleted', body.key, chipId, details);
        return res.status(200).json({ success: true });
      }
      if (action === 'bulk_delete') {
        const keys = body.keys || [];
        const failed = [];
        const deleted = [];
        for (const k of keys) {
          try {
            // Fetch license info before deleting for detailed log
            const lics = await db('licenses', 'GET', { query: `key=eq.${encodeURIComponent(k)}&select=*` });
            const lic = lics && lics[0] ? lics[0] : {};
            const chipId = lic.chip_id || null;
            let custName = 'Unassigned';
            if (lic.customer_id) {
              try { const cu = await db('customers', 'GET', { query: `id=eq.${lic.customer_id}&select=name` }); if (cu && cu[0]) custName = cu[0].name; } catch(e) {}
            }
            // Delete device first (FK constraint)
            try { await db('devices', 'DELETE', { query: `license_key=eq.${encodeURIComponent(k)}` }); } catch(e) {}
            if (chipId) { try { await db('devices', 'DELETE', { query: `chip_id=eq.${encodeURIComponent(chipId)}` }); } catch(e) {} }
            await db('licenses', 'DELETE', { query: `key=eq.${encodeURIComponent(k)}` });
            deleted.push(k);
            const details = `Admin bulk deleted | Status was: ${lic.status || 'unknown'} | Customer: ${custName}${chipId ? ' | Device: ' + chipId : ''}`;
            await log('deleted', k, chipId, details);
          } catch(e) { console.error('Delete key error:', k, e.message); failed.push(k); }
        }
        // Summary log entry
        await log('bulk_deleted', null, null, `Admin deleted ${deleted.length} key(s): ${deleted.join(', ')}`);
        if (failed.length) return res.status(500).json({ error: 'Some keys could not be deleted: ' + failed.join(', ') });
        return res.status(200).json({ success: true });
      }
      if (action === 'clear_logs') { await db('logs', 'DELETE', { query: 'id=neq.00000000-0000-0000-0000-000000000000' }); return res.status(200).json({ success: true }); }
      if (action === 'save_settings') { await db('site_settings', 'PATCH', { query: 'id=eq.1', body: body.settings }); return res.status(200).json({ success: true }); }
      if (action === 'add_payment_method') { await db('payment_methods', 'POST', { body: { name: body.name, account_number: body.account_number, account_holder: body.account_holder || '', sort_order: body.sort_order || 0 } }); return res.status(200).json({ success: true }); }
      if (action === 'delete_payment_method') { await db('payment_methods', 'DELETE', { query: `id=eq.${body.id}` }); return res.status(200).json({ success: true }); }
      if (action === 'upload_fw_url') { 
        const field = body.type === 'lcd' ? 'lcd_firmware' : 'seg_firmware';
        const d = {}; d[field] = body.filename;
        await db('site_settings', 'PATCH', { query: 'id=eq.1', body: d });
        return res.status(200).json({ success: true }); 
      }
      if (action === 'add_download') {
        await db('downloads', 'POST', { body: { name: body.name, description: body.description || '', url: body.url || '', file_type: body.file_type || 'link', sort_order: body.sort_order || 0 } });
        return res.status(200).json({ success: true });
      }
      if (action === 'delete_download') {
        await db('downloads', 'DELETE', { query: `id=eq.${body.id}` });
        return res.status(200).json({ success: true });
      }
      if (action === 'add_product') {
        await db('products', 'POST', { body: { name: body.name, description: body.description || '', price: body.price || 500, price_label: body.price_label || 'ONE-TIME PAYMENT', price_note: body.price_note || '', firmware_file: body.firmware_file || '', firmware_version: body.firmware_version || '', color: body.color || '#0ea5e9', sort_order: body.sort_order || 0 } });
        return res.status(200).json({ success: true });
      }
      if (action === 'update_product') {
        const updates = {};
        if (body.name !== undefined) updates.name = body.name;
        if (body.description !== undefined) updates.description = body.description;
        if (body.price !== undefined) updates.price = body.price;
        if (body.price_label !== undefined) updates.price_label = body.price_label;
        if (body.price_note !== undefined) updates.price_note = body.price_note;
        if (body.firmware_file !== undefined) updates.firmware_file = body.firmware_file;
        if (body.firmware_version !== undefined) updates.firmware_version = body.firmware_version;
        if (body.color !== undefined) updates.color = body.color;
        await db('products', 'PATCH', { query: `id=eq.${body.id}`, body: updates });
        return res.status(200).json({ success: true });
      }
      if (action === 'delete_product') {
        await db('products', 'DELETE', { query: `id=eq.${body.id}` });
        return res.status(200).json({ success: true });
      }
      if (action === 'test_telegram') {
        await sendTelegram('🔔 <b>Test Notification</b>\n\nYour Telegram notifications are working!\n\nN&R SOLARTECH Licensing Platform');
        return res.status(200).json({ success: true });
      }
      if (action === 'set_telegram_webhook') {
        const settings = await db('site_settings', 'GET', { query: 'id=eq.1&select=telegram_bot_token' });
        const s = settings && settings[0] ? settings[0] : {};
        if (!s.telegram_bot_token) return res.status(400).json({ error: 'Set bot token first' });
        const webhookUrl = 'https://nrsolartech-licensing.vercel.app/api';
        const r = await fetch(`https://api.telegram.org/bot${s.telegram_bot_token}/setWebhook`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: webhookUrl }) });
        const data = await r.json();
        return res.status(200).json({ success: data.ok, result: data.description || '' });
      }
      if (action === 'change_admin') {
        const updates = {};
        if (body.email) updates.email = body.email.trim().toLowerCase();
        if (body.password) updates.password_hash = hashPw(body.password);
        if (body.backupEmail !== undefined) updates.backup_email = (body.backupEmail||'').trim().toLowerCase();
        if (body.secret !== undefined) updates.secret_number = body.secret||'';
        if (Object.keys(updates).length) {
          await db('admins', 'PATCH', { query: `id=eq.${session.userId}`, body: updates });
        }
        return res.status(200).json({ success: true });
      }
      if (action === 'delete_payment') {
        await db('pending_payments', 'DELETE', { query: `id=eq.${body.paymentId}` });
        return res.status(200).json({ success: true });
      }
      if (action === 'admin_reset_customer_pw') {
        const defaultPw = '123456789';
        await db('customers', 'PATCH', { query: `id=eq.${body.customerId}`, body: { password_hash: hashPw(defaultPw) } });
        await log('admin_reset_pw', null, null, 'Admin reset customer password');
        return res.status(200).json({ success: true, message: 'Password reset to: 123456789' });
      }
      if (action === 'delete_customer') {
        // Unassign their licenses first
        await db('licenses', 'PATCH', { query: `customer_id=eq.${body.customerId}`, body: { customer_id: null } });
        // Delete their payments
        await db('pending_payments', 'DELETE', { query: `customer_id=eq.${body.customerId}` });
        // Delete customer
        await db('customers', 'DELETE', { query: `id=eq.${body.customerId}` });
        await log('delete_customer', null, null, 'Admin deleted customer');
        return res.status(200).json({ success: true });
      }
      if (action === 'reset_payments') {
        if (!body.password) return res.status(403).json({ error: 'Password required' });
        const admins = await db('admins', 'GET', { query: `id=eq.${session.userId}&select=*` });
        if (!admins || !admins.length) return res.status(403).json({ error: 'Admin not found' });
        const a = admins[0];
        if (a.password_hash !== hashPw(body.password) && a.password_hash !== body.password) return res.status(403).json({ error: 'Wrong password' });
        // Delete all payments only - licenses/customers untouched
        await db('pending_payments', 'DELETE', { query: 'id=neq.00000000-0000-0000-0000-000000000000' });
        await log('reset_payments', null, null, 'Admin reset all payments');
        return res.status(200).json({ success: true });
      }
      if (action === 'reset_customers') {
        if (!body.password) return res.status(403).json({ error: 'Password required' });
        const admins = await db('admins', 'GET', { query: `id=eq.${session.userId}&select=*` });
        if (!admins || !admins.length) return res.status(403).json({ error: 'Admin not found' });
        const a = admins[0];
        if (a.password_hash !== hashPw(body.password) && a.password_hash !== body.password) return res.status(403).json({ error: 'Wrong password' });
        // Log all licenses before deleting for recovery reference
        const allLics = await db('licenses', 'GET', { query: 'select=key,status,chip_id,customer_id' }).catch(() => []);
        const licCount = allLics ? allLics.length : 0;
        const activeKeys = allLics ? allLics.filter(l => l.status === 'active').map(l => l.key) : [];
        // Delete all devices (ESP32s will revert to trial on next verify)
        await db('devices', 'DELETE', { query: 'id=neq.00000000-0000-0000-0000-000000000000' });
        // Delete all licenses
        await db('licenses', 'DELETE', { query: 'id=neq.00000000-0000-0000-0000-000000000000' });
        // Delete all payments and customers
        await db('pending_payments', 'DELETE', { query: 'id=neq.00000000-0000-0000-0000-000000000000' });
        await db('customers', 'DELETE', { query: 'id=neq.00000000-0000-0000-0000-000000000000' });
        await db('sessions', 'DELETE', { query: 'id=neq.00000000-0000-0000-0000-000000000000' });
        await log('reset_customers', null, null, `Admin FULL RESET: deleted ${licCount} licenses (${activeKeys.length} were active: ${activeKeys.join(', ')||'none'}), all customers, payments, devices, sessions`);
        return res.status(200).json({ success: true, deletedLicenses: licCount, activeKeys });
      }
    }

      if (action === 'recover_license') {
        // Admin pastes a previously deleted/lost license key to restore it
        if (!body.key) return res.status(400).json({ error: 'License key required' });
        const key = body.key.trim().toUpperCase();
        // Validate NR key format (17 chars: NR-XXXX-XXXX-XXXX)
        if (!/^NR-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key)) return res.status(400).json({ error: 'Invalid key format. Must be NR-XXXX-XXXX-XXXX' });
        // Check if key already exists
        const existing = await db('licenses', 'GET', { query: `key=eq.${encodeURIComponent(key)}&select=id,status` });
        if (existing && existing.length) return res.status(409).json({ error: `Key already exists with status: ${existing[0].status}` });
        // Re-create as inactive, unassigned — customer can claim it again
        await db('licenses', 'POST', { body: { key, type: 'permanent', status: 'inactive' } });
        await log('recover_license', key, null, `Admin recovered license key — available for customer to claim`);
        return res.status(200).json({ success: true, key, message: 'License recovered! Customer can now claim it from their login.' });
      }

    return res.status(400).json({ error: 'Unknown action' });
  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({ error: error.message || 'Server error' });
  }
};
