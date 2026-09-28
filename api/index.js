// N&R SOLARTECH - Secure API
// service_role key is in Vercel environment variables - NEVER exposed to browser

const SB_URL = process.env.SUPABASE_URL || 'https://sdviemivuftnsytmnqaq.supabase.co';
const SB_ANON = process.env.SUPABASE_ANON_KEY || '';
const SB_SECRET = process.env.SUPABASE_SERVICE_KEY || '';

// ============================================================================
// SIGNED LICENCE ANSWERS (N&R Carwash Kiosk CWK-1.22+)
// The server signs "active" answers and its own clock with a private key kept
// ONLY in the Vercel environment variable LICENSE_SIGN_KEY (base64 PKCS8,
// ECDSA P-256). The ESP32 holds the public key and accepts an online licence
// or a clock only with a genuine signature for ITS chip, newer than the last
// one it accepted. Without the variable nothing is signed and every answer is
// exactly as before - older firmware ignores the extra fields.
// ============================================================================
const crypto = require('crypto');
let LIC_KEY = null;
try {
  if (process.env.LICENSE_SIGN_KEY)
    LIC_KEY = crypto.createPrivateKey({ key: Buffer.from(process.env.LICENSE_SIGN_KEY.trim(), 'base64'), format: 'der', type: 'pkcs8' });
} catch (e) { LIC_KEY = null; }
function signText(text) {
  return crypto.sign('sha256', Buffer.from(text, 'utf8'), { key: LIC_KEY, dsaEncoding: 'ieee-p1363' }).toString('hex');
}
/* NRLIC1|<chipId>|<key>|active|<unix time> */
function licSig(chipId, key) {
  if (!LIC_KEY) return {};
  const ts = Math.floor(Date.now() / 1000);
  return { ts, sig: signText(`NRLIC1|${String(chipId).toUpperCase()}|${key}|active|${ts}`) };
}

// ============================================================================
// CONNECTION POOL
// Limits simultaneous Supabase requests to MAX_CONCURRENT (3)
// Prevents NANO plan (15 connections max) from being overwhelmed
// when multiple ESP32 devices verify at the same time.
// Requests beyond MAX_CONCURRENT are queued and processed in order.
// ============================================================================
const MAX_CONCURRENT = 3;
let activeRequests = 0;
const requestQueue = [];

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function withRetry(fn, retries = 2, delay = 500) {
  // Exponential backoff: 500ms → 1000ms → give up
  // Only retries on 503 (service unavailable) or 521 (server down)
  // Does NOT retry on 400/403/404 — those are real errors
  for (let i = 0; i <= retries; i++) {
    try { return await fn(); }
    catch (e) {
      const isRetryable = e.message && (
        e.message.includes('503') ||
        e.message.includes('521') ||
        e.message.includes('PGRST002') ||
        e.message.includes('fetch failed')
      );
      if (i < retries && isRetryable) {
        await sleep(delay * Math.pow(2, i)); // 500ms, 1000ms
      } else { throw e; }
    }
  }
}

function pooledFetch(fn) {
  return new Promise((resolve, reject) => {
    const run = async () => {
      activeRequests++;
      try { resolve(await withRetry(fn)); }
      catch (e) { reject(e); }
      finally {
        activeRequests--;
        if (requestQueue.length > 0) requestQueue.shift()();
      }
    };
    if (activeRequests < MAX_CONCURRENT) run();
    else requestQueue.push(run);
  });
}

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
  // Use connection pool to limit simultaneous DB requests
  return pooledFetch(async () => {
    const res = await fetch(url, opts);
    if (!res.ok) { const t = await res.text(); throw new Error(`DB ${res.status}: ${t}`); }
    const ct = res.headers.get('content-type');
    if (ct && ct.includes('json')) return res.json();
    return null;
  });
}

// ============================================================================
// MEMORY CACHE — Public landing page data (site_settings, products, etc.)
// Cached for 5 minutes to reduce DB load on repeated page opens.
// Admin dashboard, license activation, payments — never cached, always live.
// Cache auto-clears after 5 minutes.
// ============================================================================
const cache = {};
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function getCached(key) {
  const entry = cache[key];
  if (!entry) return null;
  if (Date.now() - entry.time > CACHE_TTL) { delete cache[key]; return null; }
  return entry.data;
}
function setCache(key, data) { cache[key] = { data, time: Date.now() }; }

async function log(a, k, c, d) {
  try { await db('logs', 'POST', { body: { action: a, license_key: k || null, chip_id: c || null, details: d || '' } }); } catch (e) {}
}

/* 26 Sep 2026 - PRODUCT-SPECIFIC NR KEYS. A key can be made for ONE product:
   'kiosk'   = N&R Carwash Kiosk (tablet app)
   'carwash' = SmartCarwash hybrid firmware (7-segment / LCD: v26, v93-v99)
   'paykiosk'= N&R Payment Kiosk (billing kiosk: tablet app + ESP32 counter)
   null      = any product (keys made before this change, and the other
               machines: NR-CHARGER, Coin Changer, Phone Rental ...)
   The product is checked when a key is FIRST bound to a chip; after that the
   key is locked to that chip anyway. A key with no product is locked to the
   product it is first used on.
   Which product is asking - no firmware or app change was needed:
     - "product" in the request, if a newer firmware/app sends it
     - firmware "CWK..."                          -> kiosk
     - firmware "v1-LCD" / "...7SEG..." / "4IN1"  -> carwash
     - firmware "v56-SEG" is sent by BOTH the hybrid (v93-v99) and the Kiosk
       app (<= 1.0.40, copied from v94). Their FIRST activation differs: the
       Kiosk app always adds deviceStatus/failCount/wifiRSSI, the hybrid's
       activation never does (its restore does, but a restore re-binds a key
       already bound to that same chip).                                      */
const PRODUCTS = { kiosk: 'Carwash Kiosk', carwash: 'SmartCarwash hybrid', paykiosk: 'Payment Kiosk' };
const lp = v => (v === 'kiosk' || v === 'carwash' || v === 'paykiosk') ? v : null;
/* keys for an approved payment: for the product the customer paid for */
async function makeKeysForPayment(p, qty) {
  const keys = [];
  for (let i = 0; i < qty; i++) {
    const k = genKey(); const row = { key: k, type: 'permanent', status: 'inactive', customer_id: p.customer_id };
    if (lp(p.product)) row.product = p.product;
    await db('licenses', 'POST', { body: row }); keys.push(k);
  }
  return keys;
}
function requestProduct(b) {
  if (b.product === 'kiosk' || b.product === 'carwash' || b.product === 'paykiosk') return b.product;
  const fw = String(b.firmware || '');
  if (/^NR_Kiosk/i.test(fw)) return 'paykiosk';   /* the Payment Kiosk (its app sends "product" too) */
  if (/^CWK/i.test(fw)) return 'kiosk';
  if (fw === 'v56-SEG') return ('deviceStatus' in b) ? 'kiosk' : 'carwash';
  if (fw === 'v1-LCD' || /7SEG|LCD|4IN1/i.test(fw)) return 'carwash';
  return null;                                   /* another product */
}
function genKey() {
  /* 27 Sep 2026: crypto.randomInt, not Math.random - keys must not be predictable */
  const c = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const s = () => Array.from({ length: 4 }, () => c[crypto.randomInt(c.length)]).join('');
  return `NR-${s()}-${s()}-${s()}`;
}

/* PASSWORDS (27 Sep 2026). The old "h1_" hash was a 32-bit sum: millions of
   passwords share each value, and the check ALSO accepted the stored value itself
   as a password. Now: scrypt with its own random salt ("s1$salt$hash"). An old
   h1_ or plain-text password still logs in ONCE and is upgraded on the spot; the
   stored value is never accepted as a password again. */
function hashPwOld(pw) {
  let h = 0;
  const salt = 'NR$0LAR#2025!';
  const s = salt + pw + salt;
  for (let i = 0; i < s.length; i++) { h = ((h << 5) - h + s.charCodeAt(i)) | 0; }
  return 'h1_' + Math.abs(h).toString(36) + '_' + s.length;
}
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return 's1$' + salt + '$' + crypto.scryptSync(String(pw || ''), salt, 32).toString('hex');
}
/* true when the password matches; .upgrade when the stored form is an old one */
function checkPw(stored, pw) {
  stored = String(stored || ''); pw = String(pw || '');
  if (!stored || !pw) return { ok: false };
  if (stored.startsWith('s1$')) {
    const [, salt, hex] = stored.split('$');
    if (!salt || !hex) return { ok: false };
    const a = Buffer.from(hex, 'hex'), b = crypto.scryptSync(pw, salt, 32);
    return { ok: a.length === b.length && crypto.timingSafeEqual(a, b) };
  }
  if (stored.startsWith('h1_')) return { ok: hashPwOld(pw) === stored, upgrade: true };
  return { ok: stored === pw, upgrade: true };            /* a plain-text leftover */
}
async function upgradePw(table, id, pw) {
  try { await db(table, 'PATCH', { query: `id=eq.${encodeURIComponent(id)}`, body: { password_hash: hashPw(pw) } }); } catch (e) {}
}
function tempPassword() {
  const c = 'abcdefghjkmnpqrstuvwxyz23456789';
  return Array.from({ length: 10 }, () => c[crypto.randomInt(c.length)]).join('');
}
/* a chip / device id: letters, digits and : - _ only (it is shown in the admin page) */
const cleanId = v => { const s = String(v || '').trim(); return /^[A-Za-z0-9:_-]{4,40}$/.test(s) ? s : ''; };
const cleanText = (v, n) => String(v == null ? '' : v).replace(/[<>\u0000-\u001f]/g, '').trim().slice(0, n || 100);
const clientIp = req => String(req.headers['x-real-ip'] || String(req.headers['x-forwarded-for'] || '').split(',')[0] || '').trim();
/* failed secret-number attempts per account, counted in the logs table so a
   cold start or another server instance cannot reset them */
async function recentFails(action, who, minutes) {
  try {
    const since = new Date(Date.now() - minutes * 60000).toISOString();
    const r = await db('logs', 'GET', { query: `action=eq.${action}&details=eq.${encodeURIComponent(who)}&timestamp=gte.${encodeURIComponent(since)}&select=id` });
    return (r || []).length;
  } catch (e) { return 0; }
}
const sha256 = t => crypto.createHash('sha256').update(String(t || '')).digest('hex');

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
  const token = crypto.randomBytes(24).toString('hex');   /* 27 Sep 2026: not Math.random */
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
  // Health check endpoint — GET /api?health=1
  if (req.method === 'GET') {
    try {
      await db('site_settings', 'GET', { query: 'id=eq.1&select=id' });
      return res.status(200).json({ ok: true, db: 'healthy' });
    } catch(e) {
      return res.status(503).json({ ok: false, db: 'unhealthy' });
    }
  }
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const ip = clientIp(req);
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
      const settings = await db('site_settings', 'GET', { query: 'id=eq.1&select=*' });
      const s = settings && settings[0] ? settings[0] : {};
      if (!s.telegram_bot_token || String(chatId) !== String(s.telegram_chat_id)) return res.status(200).json({ ok: true });
      /* 27 Sep 2026: ONLY TELEGRAM ITSELF. The chat id alone was the check, and the
         bot token and chat id were readable by anyone - a forged "/approve" gave
         free keys. Telegram sends back the secret given to it by "Set webhook";
         without that secret nothing is approved (press Set webhook once). */
      const tgSecret = String(req.headers['x-telegram-bot-api-secret-token'] || '');
      if (!s.telegram_webhook_secret || tgSecret.length !== String(s.telegram_webhook_secret).length ||
          !crypto.timingSafeEqual(Buffer.from(tgSecret), Buffer.from(String(s.telegram_webhook_secret)))) {
        await log('telegram_refused', null, null, 'webhook without the secret');
        return res.status(200).json({ ok: true });
      }
      
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
        keys.push(...await makeKeysForPayment(p, qty));
        await log('payment_approved', keys[0], null, 'Telegram: ' + p.customer_name + ' ref:' + ref + ' x' + qty + (lp(p.product) ? ' for ' + PRODUCTS[p.product] : ''));
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
      const regName = cleanText(body.name, 50), regEmail = String(body.email).trim().toLowerCase();
      if (!regName) return res.status(400).json({ error: 'Enter your name' });
      if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(regEmail)) return res.status(400).json({ error: 'Enter a valid email' });
      if (!/^[0-9]{4,6}$/.test(String(body.secret))) return res.status(400).json({ error: 'Secret number must be 4-6 digits' });
      const r = await db('customers', 'POST', { body: { name: regName, phone: cleanText(body.phone, 30), email: regEmail, password_hash: hashPw(body.password), secret_number: String(body.secret) } });
      const token = await createSession(r[0].id, 'c');
      await log('register', null, null, regName + ' registered (' + regEmail + ')');
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
      const pc = checkPw(c.password_hash, password);
      if (!pc.ok) return res.status(401).json({ error: 'Invalid email or password' });
      if (pc.upgrade) await upgradePw('customers', c.id, password);
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
      const pa = checkPw(a.password_hash, body.password);
      if (!pa.ok) { await log('admin_login_failed', null, null, 'from ' + ip); return res.status(401).json({ error: 'Invalid credentials' }); }
      if (pa.upgrade) await upgradePw('admins', a.id, body.password);
      if (String(body.password) === 'admin123' || String(body.password) === '123456789')
        sendTelegram('\u26A0\uFE0F <b>Admin signed in with a DEFAULT password</b> - change it now (Admin > Settings).');
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
      /* 27 Sep 2026: 5 wrong secret numbers in an hour lock THIS account for an
         hour (counted in the database), and the new password is random - it
         was always 123456789 */
      if (await recentFails('forgot_failed', c.email, 60) >= 5) return res.status(429).json({ error: 'Too many wrong secret numbers for this account. Try again in an hour.' });
      if (String(c.secret_number) !== String(body.secret)) { await log('forgot_failed', null, null, c.email); return res.status(403).json({ error: 'Wrong secret number' }); }
      const tempPw = tempPassword();
      await db('customers', 'PATCH', { query: `id=eq.${c.id}`, body: { password_hash: hashPw(tempPw) } });
      await log('password_reset', null, null, 'Customer reset via secret: ' + c.email);
      return res.status(200).json({ success: true, password: tempPw, message: 'Your new password is: ' + tempPw + ' - log in and change it.' });
    }

    // ==================== ADMIN FORGOT (no auth needed) ====================
    if (action === 'admin_forgot') {
      if (!body.backupEmail || !body.secret) return res.status(400).json({ error: 'Backup email and secret number required' });
      if (!rateLimit('adminforgot_' + ip, 3, 600000)) return res.status(429).json({ error: 'Too many attempts. Wait 10 minutes.' });
      const admins = await db('admins', 'GET', { query: `backup_email=eq.${encodeURIComponent((body.backupEmail||'').trim().toLowerCase())}&select=*` });
      if (!admins || !admins.length) return res.status(404).json({ error: 'Backup email not found' });
      const a = admins[0];
      if (await recentFails('admin_forgot_failed', a.email, 60) >= 3) return res.status(429).json({ error: 'Too many wrong secret numbers. Try again in an hour.' });
      if (String(a.secret_number) !== String(body.secret)) {
        await log('admin_forgot_failed', null, null, a.email);
        sendTelegram('\u26A0\uFE0F <b>Wrong secret number</b> on the ADMIN password reset (from ' + ip + ').');
        return res.status(403).json({ error: 'Wrong secret number' });
      }
      const tempPw = tempPassword();
      await db('admins', 'PATCH', { query: `id=eq.${a.id}`, body: { password_hash: hashPw(tempPw) } });
      await log('admin_reset', null, null, 'Admin password reset via backup email');
      sendTelegram('\u26A0\uFE0F <b>The ADMIN password was reset</b> with the backup email (from ' + ip + '). If this was not you, act now.');
      return res.status(200).json({ success: true, loginEmail: a.email, password: tempPw, message: 'Your new admin password is: ' + tempPw + ' - log in and change it.' });
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

    // Signed clock for a device (NRTIME1|<chipId>|<unix time>) - T-keys, replay order
    if (action === 'signed_time') {
      const chipId = cleanId(body.chipId);
      if (!chipId) return res.status(400).json({ status: 'error', message: 'Missing chipId' });
      if (!rateLimit('time_' + ip, 30, 60000)) return res.status(429).json({ status: 'error', message: 'Rate limited' });
      const ts = Math.floor(Date.now() / 1000);
      if (!LIC_KEY) return res.status(200).json({ ts });
      return res.status(200).json({ ts, sig: signText(`NRTIME1|${String(chipId).toUpperCase()}|${ts}`) });
    }

    if (action === 'activate_device') {
      const key = String(body.key || '').trim().toUpperCase().slice(0, 40), chipId = cleanId(body.chipId), firmware = cleanText(body.firmware, 40);
      if (!key || !chipId) return res.status(400).json({ status: 'error', message: 'Missing key or chipId' });
      if (!rateLimit('actip_' + ip, 30, 600000)) return res.status(429).json({ status: 'error', message: 'Rate limited' });
      if (!rateLimit('act_' + chipId, 10, 600000)) return res.status(429).json({ status: 'error', message: 'Rate limited' });
      const lics = await db('licenses', 'GET', { query: `key=eq.${encodeURIComponent(key)}&select=*` });
      if (!lics || !lics.length) { await log('activate_failed', key, chipId, 'Invalid key'); return res.status(404).json({ status: 'error', error: 'notFound', message: 'This key does not exist on the licensing server' }); }
      const l = lics[0];
      if (l.status === 'revoked') return res.status(403).json({ status: 'error', error: 'revoked', message: 'License revoked' });
      if (l.status === 'suspended') return res.status(403).json({ status: 'error', error: 'suspended', message: 'License suspended' });
      /* 28 Sep 2026: say WHICH machine has it (last 4 of its ID) so the owner can tell */
      if (l.status === 'active' && l.chip_id && l.chip_id !== chipId) {
        const chipEnd = String(l.chip_id).slice(-4);
        await log('activate_failed', key, chipId, 'Key active on another device ...' + chipEnd);
        return res.status(409).json({ status: 'error', error: 'otherDevice', chipEnd, message: 'This key is already active on another machine (ID ending ' + chipEnd + ')' });
      }
      if (l.status === 'active' && l.chip_id === chipId) return res.status(200).json({ status: 'active', message: 'Already activated', ...licSig(chipId, key) });
      const asking = requestProduct(body);
      if (l.product && asking !== l.product) {
        /* 28 Sep 2026: was this key used before (bound once, then freed)? Then the
           owner must hear "already used", not "made for another product" */
        let usedBefore = !!(l.activated_at || l.chip_id || (l.transfer_count > 0));
        if (!usedBefore) { try { const lg = await db('logs', 'GET', { query: `license_key=eq.${encodeURIComponent(key)}&action=in.(activate,transfer_device,transfer_account)&select=id&limit=1` }); usedBefore = !!(lg && lg.length); } catch (e) {} }
        await log('activate_failed', key, chipId, 'Wrong product: key for ' + l.product + ', asked by ' + (asking || 'another product') + (usedBefore ? ' (key used before)' : ''));
        return res.status(403).json({ status: 'error', error: 'wrongProduct', product: l.product, usedBefore,
          message: usedBefore ? 'This key was already used before and is locked to the ' + PRODUCTS[l.product] + ' - it cannot activate this machine'
                              : 'This key is for the ' + PRODUCTS[l.product] + ' - not this machine' });
      }
      const bind = { status: 'active', chip_id: chipId, activated_at: new Date().toISOString() };
      if (!l.product && asking && ('product' in l)) bind.product = asking;   /* lock an untagged key to its first product (only once the column exists) */
      await db('licenses', 'PATCH', { query: `key=eq.${encodeURIComponent(key)}`, body: bind });
      try {
        const now = new Date().toISOString();
        const devs = await db('devices', 'GET', { query: `chip_id=eq.${encodeURIComponent(chipId)}&select=id,activated_at` });
        if (devs && devs.length) {
          // Update existing device — preserve activated_at if already set
          const existingActivatedAt = devs[0].activated_at || now;
          await db('devices', 'PATCH', { query: `chip_id=eq.${encodeURIComponent(chipId)}`, body: { firmware_version: firmware || '', last_seen: now, ip_address: ip, license_key: key, activated_at: existingActivatedAt } });
        } else {
          // New device — set activated_at now
          await db('devices', 'POST', { body: { chip_id: chipId, firmware_version: firmware || '', last_seen: now, ip_address: ip, license_key: key, activated_at: now } });
        }
      } catch (e) {}
      await log('activate', key, chipId, 'Activated');
      return res.status(200).json({ status: 'active', message: 'License activated!', ...licSig(chipId, key) });
    }

    // ==================== ESP32: Verify ====================
    if (action === 'verify_device') {
      if (!rateLimit('verify_' + ip, 30, 60000)) return res.status(429).json({ status: 'error', message: 'Rate limited' });
      const key = String(body.key || '').trim().toUpperCase().slice(0, 40), chipId = cleanId(body.chipId), firmware = cleanText(body.firmware, 40);
      const deviceStatus = cleanText(body.deviceStatus, 20), wifiRSSI = Number(body.wifiRSSI) || 0;
      if (!key || !chipId) return res.status(400).json({ status: 'error', message: 'Missing' });
      const lics = await db('licenses', 'GET', { query: `key=eq.${encodeURIComponent(key)}&select=*` });
      if (!lics || !lics.length) return res.status(404).json({ status: 'invalid' });
      const l = lics[0];
      /* 27 Sep 2026: only the chip the key is bound to may update its device row -
         anyone could rewrite any device's firmware / status text before */
      const mine = l.chip_id && l.chip_id === chipId;
      if (mine) try { await db('devices', 'PATCH', { query: `chip_id=eq.${encodeURIComponent(chipId)}`, body: { last_seen: new Date().toISOString(), ip_address: ip, firmware_version: firmware, device_status: deviceStatus || 'unknown', wifi_rssi: wifiRSSI } }); } catch (e) {}
      // Also backfill activated_at if missing (for devices activated before v18)
      if (mine) try {
        const dv = await db('devices', 'GET', { query: `chip_id=eq.${encodeURIComponent(chipId)}&select=activated_at` });
        if (dv && dv.length && !dv[0].activated_at) {
          const lic = await db('licenses', 'GET', { query: `key=eq.${encodeURIComponent(key)}&select=activated_at` });
          const ts = (lic && lic.length && lic[0].activated_at) ? lic[0].activated_at : new Date().toISOString();
          await db('devices', 'PATCH', { query: `chip_id=eq.${encodeURIComponent(chipId)}`, body: { activated_at: ts } });
        }
      } catch(e) {}
      if (l.status === 'active' && l.chip_id === chipId) return res.status(200).json({ status: 'active', verify: 'ok', ...licSig(chipId, key) });
      if (l.status === 'suspended') return res.status(403).json({ status: 'suspended', verify: 'fail' });
      if (l.status === 'revoked') return res.status(403).json({ status: 'revoked', verify: 'fail' });
      return res.status(403).json({ status: 'inactive', verify: 'fail' });
    }

    // ==================== SALES FROM THE KEYGEN (27 Sep 2026) ====================
    /* Every key made in the NR KeyGen (SmartCarwash P/T, Carwash Kiosk P/T, Payment
       Kiosk P, Solar Quotation, deactivations) can be recorded here so the site's
       accounting counts it. Allowed with the KeyGen's POSTING KEY (made in Admin >
       Accounting; it can do nothing else) or an admin session. A sale is stored as
       an APPROVED payment with source 'keygen', so every total on the site includes
       it. The KeyGen's own id for the sale (external_ref) makes a repeat harmless. */
    if (action === 'record_sale') {
      if (!rateLimit('sale_' + ip, 60, 60000)) return res.status(429).json({ error: 'Too many requests' });
      let who = '';
      const posting = String(req.headers['x-keygen-token'] || body.keygenToken || '');
      if (posting) {
        const st = await db('site_settings', 'GET', { query: 'id=eq.1&select=*' });
        const want = st && st[0] ? String(st[0].keygen_token_hash || '') : '';
        if (!want || sha256(posting) !== want) { await log('sale_refused', null, null, 'wrong KeyGen posting key from ' + ip); return res.status(401).json({ error: 'Wrong KeyGen posting key - make a new one in Admin > Accounting' }); }
        who = 'KeyGen';
      } else {
        const ses = await getSession(authToken);
        if (!ses || ses.type !== 'a') return res.status(401).json({ error: 'Not authenticated. Please login again.' });
        who = 'Admin';
      }
      const SALE_PRODUCTS = { carwash: 'SmartCarwash', kiosk: 'Carwash Kiosk', paykiosk: 'Payment Kiosk', quotation: 'Solar Quotation', other: 'Other product' };
      const KEY_TYPES = ['permanent', 'temporary', 'deactivation', 'quotation', 'online'];
      const product = SALE_PRODUCTS[body.product] ? body.product : '';
      const keyType = KEY_TYPES.includes(body.keyType) ? body.keyType : '';
      const amount = Number(body.amount);
      if (!product) return res.status(400).json({ error: 'Choose the product' });
      if (!keyType) return res.status(400).json({ error: 'Unknown key type' });
      if (!(amount >= 0 && amount <= 10000000)) return res.status(400).json({ error: 'Enter the amount (0 or more)' });
      const ext = cleanText(body.saleId, 80);
      if (ext) {
        const dup = await db('pending_payments', 'GET', { query: `external_ref=eq.${encodeURIComponent(ext)}&select=id,amount,customer_name` }).catch(() => []);
        if (dup && dup.length) return res.status(200).json({ success: true, duplicate: true, id: dup[0].id });
      }
      const soldAt = /^\d{4}-\d{2}-\d{2}/.test(String(body.soldAt || '')) && !isNaN(Date.parse(body.soldAt)) ? new Date(body.soldAt).toISOString() : new Date().toISOString();
      const row = {
        customer_id: null, customer_name: cleanText(body.customer, 80) || 'Walk-in customer',
        amount: Math.round(amount), method: cleanText(body.method, 30) || 'Cash',
        ref_number: cleanText(body.ref, 50), status: 'approved', quantity: 1, submitted_at: soldAt,
        product, product_name: SALE_PRODUCTS[product], source: 'keygen',
        license_key: cleanText(body.licenseKey, 120), chip_id: cleanText(body.chipId, 40),
        key_type: keyType, notes: cleanText(body.notes, 200), external_ref: ext || null
      };
      let made;
      try { made = await db('pending_payments', 'POST', { body: row }); }
      catch (e) { console.error('record_sale', e.message); return res.status(500).json({ error: 'Could not record the sale - has the accounting SQL been run on the site?' }); }
      await log('sale_recorded', row.license_key || null, row.chip_id || null, who + ': ' + SALE_PRODUCTS[product] + ' ' + keyType + ' P' + row.amount + ' - ' + row.customer_name);
      if (row.amount > 0) sendTelegram('\uD83E\uDDFE <b>Sale recorded</b> (' + who + ')\n' + SALE_PRODUCTS[product] + ' \u00b7 ' + keyType + '\n\uD83D\uDC64 ' + row.customer_name + '\n\uD83D\uDCB5 \u20B1' + row.amount);
      return res.status(200).json({ success: true, id: made && made[0] ? made[0].id : null });
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
        /* 27 Sep 2026: the name search is gone - a customer named "a" received every
           log line containing an "a": other customers' names, emails and keys */
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
        if (!checkPw(me.password_hash, body.password).ok) return res.status(403).json({ error: 'Wrong password' });
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
        if (!checkPw(me.password_hash, body.password).ok) return res.status(403).json({ error: 'Wrong password' });
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
        const payRow = { customer_id: uid, customer_name: name, amount: Math.max(0, Math.min(1000000, parseInt(body.amount, 10) || 500)), method: cleanText(body.method || 'GCash', 30),
                         ref_number: cleanText(body.refNumber, 50), proof_url: /^https:\/\/[^\s<>"']+$/.test(String(body.proofUrl || '')) ? String(body.proofUrl).slice(0, 500) : '', quantity: Math.max(1, Math.min(100, parseInt(qty, 10) || 1)) };
        /* 26 Sep 2026: the product the customer is paying for - its keys will work only on that machine */
        let prod = null, prodName = '';
        if (body.productId) { try { const pr = await db('products', 'GET', { query: `id=eq.${encodeURIComponent(body.productId)}&select=name,license_product` }); if (pr && pr.length) { prod = lp(pr[0].license_product); prodName = pr[0].name || ''; } } catch (e) {} }
        try { await db('pending_payments', 'POST', { body: Object.assign({}, payRow, { product: prod, product_name: prodName }) }); }
        catch (e) { await db('pending_payments', 'POST', { body: payRow }); }   /* before the SQL: without the new columns */
        await log('payment_submitted', null, null, name + ' submitted ' + (body.method || 'GCash') + ' payment');
        // Notify admin via Telegram
        sendTelegram(`💰 <b>New Payment!</b>\n\n👤 ${name}\n💳 ${body.method || 'GCash'}\n💵 ₱${body.amount || 500}\n🔑 Keys for: ${prod ? PRODUCTS[prod] : 'any product'}\n📝 Ref: ${(body.refNumber || 'N/A').substring(0, 50)}`);
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
        if (!checkPw(c.password_hash, body.oldPassword).ok) return res.status(403).json({ error: 'Current password is wrong' });
        await db('customers', 'PATCH', { query: `id=eq.${uid}`, body: { password_hash: hashPw(body.newPassword) } });
        await log('password_changed', null, null, c.name + ' changed password');
        return res.status(200).json({ success: true });
      }
      if (action === 'change_customer_email') {
        if (!body.newEmail || !body.password) return res.status(400).json({ error: 'New email and password required' });
        const custs = await db('customers', 'GET', { query: `id=eq.${uid}&select=*` });
        if (!custs || !custs.length) return res.status(404).json({ error: 'Not found' });
        const c = custs[0];
        if (!checkPw(c.password_hash, body.password).ok) return res.status(403).json({ error: 'Wrong password' });
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
        const st0 = Object.assign({}, (settings && settings[0]) || {});
        st0.keygen_token_set = !!st0.keygen_token_hash; st0.telegram_webhook_secured = !!st0.telegram_webhook_secret;
        delete st0.keygen_token_hash; delete st0.telegram_webhook_secret;
        return res.status(200).json({ licenses, customers, devices, logs, payments, settings: st0, pms: pms || [], downloads: dls || [], products: products || [] });
      }
      if (action === 'make_keygen_token') {
        /* shown ONCE; the site keeps only its sha256 */
        const tok = 'kg_' + crypto.randomBytes(24).toString('hex');
        try { await db('site_settings', 'PATCH', { query: 'id=eq.1', body: { keygen_token_hash: sha256(tok) } }); }
        catch (e) { return res.status(500).json({ error: 'Run the accounting SQL on the site first' }); }
        await log('keygen_token', null, null, 'Admin made a new KeyGen posting key');
        return res.status(200).json({ success: true, token: tok });
      }
      if (action === 'revoke_keygen_token') {
        try { await db('site_settings', 'PATCH', { query: 'id=eq.1', body: { keygen_token_hash: '' } }); } catch (e) {}
        await log('keygen_token', null, null, 'Admin removed the KeyGen posting key');
        return res.status(200).json({ success: true });
      }
      if (action === 'create_license') {
        const n = Math.min(body.count || 1, 100);
        const keys = [];
        const product = lp(body.product);
        for (let i = 0; i < n; i++) { const k = genKey(); const row = { key: k, type: 'permanent', status: 'inactive' }; if (product) row.product = product; await db('licenses', 'POST', { body: row }); keys.push(k); }
        await log('created', keys[0], null, 'Admin generated ' + n + ' keys for ' + (product ? PRODUCTS[product] : 'any product'));
        return res.status(200).json({ success: true, keys, product });
      }
      if (action === 'approve_payment') {
        const pays = await db('pending_payments', 'GET', { query: `id=eq.${encodeURIComponent(body.paymentId)}&select=*` });
        if (!pays || !pays.length) return res.status(404).json({ error: 'Not found' });
        const p = pays[0];
        await db('pending_payments', 'PATCH', { query: `id=eq.${encodeURIComponent(body.paymentId)}`, body: { status: 'approved' } });
        const qty = p.quantity || 1;
        const keys = [];
        keys.push(...await makeKeysForPayment(p, qty));
        await log('payment_approved', keys[0], null, `${p.method} P${p.amount} ${p.customer_name} x${qty}` + (lp(p.product) ? ' for ' + PRODUCTS[p.product] : ''));
        sendTelegram(`✅ <b>APPROVED!</b>\n\n👤 ${p.customer_name}\n💳 ${p.method}\n💵 ₱${p.amount}${qty > 1 ? ' (' + qty + ' licenses)' : ''}\n📝 Ref: ${p.ref_number || 'N/A'}\n🔑 ${keys.map(k => '<code>' + k + '</code>').join('\n🔑 ')}`);
        return res.status(200).json({ success: true, keys: keys });
      }
      if (action === 'reject_payment') {
        const pays = await db('pending_payments', 'GET', { query: `id=eq.${encodeURIComponent(body.paymentId)}&select=*` });
        const p = pays && pays[0] ? pays[0] : {};
        await db('pending_payments', 'PATCH', { query: `id=eq.${encodeURIComponent(body.paymentId)}`, body: { status: 'rejected' } });
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
      if (action === 'save_settings') {
        const st = Object.assign({}, body.settings || {});
        ['id', 'keygen_token_hash', 'telegram_webhook_secret', 'keygen_token_set', 'telegram_webhook_secured'].forEach(k => delete st[k]);   /* never from the form */
        await db('site_settings', 'PATCH', { query: 'id=eq.1', body: st }); return res.status(200).json({ success: true });
      }
      if (action === 'add_payment_method') { await db('payment_methods', 'POST', { body: { name: body.name, account_number: body.account_number, account_holder: body.account_holder || '', sort_order: body.sort_order || 0 } }); return res.status(200).json({ success: true }); }
      if (action === 'delete_payment_method') { await db('payment_methods', 'DELETE', { query: `id=eq.${encodeURIComponent(body.id)}` }); return res.status(200).json({ success: true }); }
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
      if (action === 'edit_download') {
        // PATCH only the fields that were actually sent, so editing a name
        // cannot silently blank the description or the url.
        const d = {};
        if (body.name !== undefined)        d.name = body.name;
        if (body.description !== undefined) d.description = body.description;
        if (body.url !== undefined)         d.url = body.url;
        if (body.sort_order !== undefined)  d.sort_order = body.sort_order;
        if (body.active !== undefined)      d.active = !!body.active;
        if (!Object.keys(d).length) return res.status(200).json({ success: true });
        await db('downloads', 'PATCH', { query: `id=eq.${encodeURIComponent(body.id)}`, body: d });
        return res.status(200).json({ success: true });
      }
      if (action === 'delete_download') {
        await db('downloads', 'DELETE', { query: `id=eq.${encodeURIComponent(body.id)}` });
        return res.status(200).json({ success: true });
      }
      if (action === 'add_product') {
        await db('products', 'POST', { body: { ...(lp(body.license_product) ? { license_product: body.license_product } : {}), name: body.name, description: body.description || '', price: body.price || 500, price_label: body.price_label || 'ONE-TIME PAYMENT', price_note: body.price_note || '', firmware_file: body.firmware_file || '', firmware_version: body.firmware_version || '', color: body.color || '#0ea5e9', sort_order: body.sort_order || 0 } });
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
        if (body.license_product !== undefined) updates.license_product = lp(body.license_product);
        await db('products', 'PATCH', { query: `id=eq.${encodeURIComponent(body.id)}`, body: updates });
        return res.status(200).json({ success: true });
      }
      if (action === 'delete_product') {
        await db('products', 'DELETE', { query: `id=eq.${encodeURIComponent(body.id)}` });
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
        /* 27 Sep 2026: a new secret every time; Telegram sends it back on every update */
        const secret = crypto.randomBytes(24).toString('hex');
        try { await db('site_settings', 'PATCH', { query: 'id=eq.1', body: { telegram_webhook_secret: secret } }); }
        catch (e) { return res.status(500).json({ error: 'Run the security SQL on the site first' }); }
        const r = await fetch(`https://api.telegram.org/bot${s.telegram_bot_token}/setWebhook`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: webhookUrl, secret_token: secret }) });
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
        await db('pending_payments', 'DELETE', { query: `id=eq.${encodeURIComponent(body.paymentId)}` });
        return res.status(200).json({ success: true });
      }
      if (action === 'admin_reset_customer_pw') {
        const tempPw = tempPassword();   /* 27 Sep 2026: random, not 123456789 */
        await db('customers', 'PATCH', { query: `id=eq.${encodeURIComponent(body.customerId)}`, body: { password_hash: hashPw(tempPw) } });
        await log('admin_reset_pw', null, null, 'Admin reset customer password');
        return res.status(200).json({ success: true, password: tempPw, message: 'New password: ' + tempPw + ' - give it to the customer.' });
      }
      if (action === 'delete_customer') {
        // Unassign their licenses first
        await db('licenses', 'PATCH', { query: `customer_id=eq.${encodeURIComponent(body.customerId)}`, body: { customer_id: null } });
        // Delete their payments
        await db('pending_payments', 'DELETE', { query: `customer_id=eq.${encodeURIComponent(body.customerId)}` });
        // Delete customer
        await db('customers', 'DELETE', { query: `id=eq.${encodeURIComponent(body.customerId)}` });
        await log('delete_customer', null, null, 'Admin deleted customer');
        return res.status(200).json({ success: true });
      }
      if (action === 'reset_payments') {
        if (!body.password) return res.status(403).json({ error: 'Password required' });
        const admins = await db('admins', 'GET', { query: `id=eq.${session.userId}&select=*` });
        if (!admins || !admins.length) return res.status(403).json({ error: 'Admin not found' });
        const a = admins[0];
        if (!checkPw(a.password_hash, body.password).ok) return res.status(403).json({ error: 'Wrong password' });
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
        if (!checkPw(a.password_hash, body.password).ok) return res.status(403).json({ error: 'Wrong password' });
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
        // FIX v20: exclude current admin session so admin stays logged in after reset
        const currentToken = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
        if (currentToken) {
          await db('sessions', 'DELETE', { query: `token=neq.${encodeURIComponent(currentToken)}` });
        } else {
          await db('sessions', 'DELETE', { query: 'token=neq.~' });
        }
        await log('reset_customers', null, null, `Admin FULL RESET: deleted ${licCount} licenses (${activeKeys.length} were active: ${activeKeys.join(', ')||'none'}), all customers, payments, devices, sessions`);
        return res.status(200).json({ success: true, deletedLicenses: licCount, activeKeys });
      }

      /* 27 Sep 2026: MOVED INSIDE the admin block. It stood after it, so ANY logged-in
         customer could create a key, claim it and activate a machine for free. */
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
    }

    return res.status(400).json({ error: 'Unknown action' });
  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({ error: 'Server error - please try again' });   /* 27 Sep 2026: no database details */
  }
};
