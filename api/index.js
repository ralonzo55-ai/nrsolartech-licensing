// N&R SOLARTECH - Secure API
// service_role key is in Vercel environment variables - NEVER exposed to browser

const SB_URL = process.env.SUPABASE_URL || 'https://sdviemivuftnsytmnqaq.supabase.co';
const SB_ANON = process.env.SUPABASE_ANON_KEY || '';
const SB_SECRET = process.env.SUPABASE_SERVICE_KEY || '';

async function db(table, method, options = {}) {
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

// Rate limiter (in-memory, resets on cold start)
const attempts = {};
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  if (!attempts[key]) attempts[key] = [];
  attempts[key] = attempts[key].filter(t => now - t < windowMs);
  if (attempts[key].length >= max) return false;
  attempts[key].push(now);
  return true;
}

// Session tokens (in-memory)
const sessions = {};
function createSession(userId, type) {
  const token = Array.from({ length: 32 }, () => 'abcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random() * 36)]).join('');
  sessions[token] = { userId, type, created: Date.now() };
  // Clean old sessions (>24hr)
  for (const t in sessions) { if (Date.now() - sessions[t].created > 86400000) delete sessions[t]; }
  return token;
}
function getSession(token) {
  const s = sessions[token];
  if (!s) return null;
  if (Date.now() - s.created > 86400000) { delete sessions[token]; return null; }
  return s;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || '';
  const authToken = (req.headers.authorization || '').replace('Bearer ', '');

  try {
    const body = req.body || {};
    const { action } = body;

    // ==================== AUTH: Register ====================
    if (action === 'register') {
      if (!body.name || !body.email || !body.password) return res.status(400).json({ error: 'All fields required' });
      if (body.password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });
      if (!rateLimit('reg_' + ip, 5, 3600000)) return res.status(429).json({ error: 'Too many registrations. Try again later.' });
      const ex = await db('customers', 'GET', { query: `email=eq.${encodeURIComponent(body.email)}&select=id` });
      if (ex && ex.length) return res.status(409).json({ error: 'Email already registered' });
      const r = await db('customers', 'POST', { body: { name: body.name.trim(), phone: body.phone || '', email: body.email.trim().toLowerCase(), password_hash: hashPw(body.password) } });
      const token = createSession(r[0].id, 'c');
      return res.status(200).json({ success: true, customer: { id: r[0].id, name: r[0].name, email: r[0].email, phone: r[0].phone }, token });
    }

    // ==================== AUTH: Customer Login ====================
    if (action === 'login') {
      if (!rateLimit('login_' + ip, 10, 600000)) return res.status(429).json({ error: 'Too many login attempts. Wait 10 minutes.' });
      const custs = await db('customers', 'GET', { query: `email=eq.${encodeURIComponent((body.email || '').trim().toLowerCase())}&select=*` });
      if (!custs || !custs.length) return res.status(401).json({ error: 'Invalid email or password' });
      // Support both old plain text and new hashed passwords
      const c = custs[0];
      if (c.password_hash !== hashPw(body.password) && c.password_hash !== body.password) return res.status(401).json({ error: 'Invalid email or password' });
      // Upgrade plain text password to hashed
      if (c.password_hash === body.password) { try { await db('customers', 'PATCH', { query: `id=eq.${c.id}`, body: { password_hash: hashPw(body.password) } }); } catch (e) {} }
      const token = createSession(c.id, 'c');
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
      const token = createSession(a.id, 'a');
      return res.status(200).json({ success: true, admin: { email: a.email }, token });
    }

    // ==================== ESP32: Activate ====================
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
      const { key, chipId, firmware } = body;
      if (!key || !chipId) return res.status(400).json({ status: 'error', message: 'Missing' });
      const lics = await db('licenses', 'GET', { query: `key=eq.${encodeURIComponent(key)}&select=*` });
      if (!lics || !lics.length) return res.status(404).json({ status: 'invalid' });
      const l = lics[0];
      try { await db('devices', 'PATCH', { query: `chip_id=eq.${encodeURIComponent(chipId)}`, body: { last_seen: new Date().toISOString(), ip_address: ip, firmware_version: firmware || '' } }); } catch (e) {}
      if (l.status === 'active' && l.chip_id === chipId) return res.status(200).json({ status: 'active' });
      if (l.status === 'suspended') return res.status(403).json({ status: 'suspended' });
      if (l.status === 'revoked') return res.status(403).json({ status: 'revoked' });
      return res.status(403).json({ status: 'inactive' });
    }

    // ==================== AUTHENTICATED ROUTES ====================
    const session = getSession(authToken);
    if (!session) return res.status(401).json({ error: 'Not authenticated. Please login again.' });

    // ---------- CUSTOMER ROUTES ----------
    if (session.type === 'c') {
      const uid = session.userId;

      if (action === 'my_licenses') {
        const lics = await db('licenses', 'GET', { query: `customer_id=eq.${uid}&select=*` });
        return res.status(200).json({ licenses: lics || [] });
      }
      if (action === 'my_logs') {
        const lics = await db('licenses', 'GET', { query: `customer_id=eq.${uid}&select=key` });
        const keys = (lics || []).map(l => l.key);
        if (!keys.length) return res.status(200).json({ logs: [] });
        let all = [];
        for (const k of keys) { const logs = await db('logs', 'GET', { query: `license_key=eq.${encodeURIComponent(k)}&select=*&order=timestamp.desc&limit=20` }); if (logs) all = all.concat(logs); }
        all.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        return res.status(200).json({ logs: all.slice(0, 30) });
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
        const lics = await db('licenses', 'GET', { query: `key=eq.${encodeURIComponent(body.key)}&select=*` });
        if (!lics || !lics.length) return res.status(404).json({ error: 'Not found' });
        const l = lics[0];
        if (l.customer_id !== uid) return res.status(403).json({ error: 'Not your license' });
        if (l.transfer_count >= l.max_transfers) return res.status(403).json({ error: 'Transfer limit reached' });
        if (!body.confirmChipId || body.confirmChipId.toUpperCase().trim() !== (l.chip_id || '').toUpperCase().trim()) return res.status(403).json({ error: 'Chip ID does not match' });
        await db('licenses', 'PATCH', { query: `key=eq.${encodeURIComponent(body.key)}`, body: { status: 'inactive', chip_id: null, activated_at: null, transfer_count: l.transfer_count + 1 } });
        try { if (l.chip_id) await db('devices', 'DELETE', { query: `chip_id=eq.${encodeURIComponent(l.chip_id)}` }); } catch (e) {}
        await log('transfer', body.key, l.chip_id, 'Transfer #' + (l.transfer_count + 1));
        return res.status(200).json({ success: true });
      }
      if (action === 'submit_payment') {
        if (!rateLimit('pay_' + uid, 3, 3600000)) return res.status(429).json({ error: 'Too many submissions. Wait 1 hour.' });
        const custs = await db('customers', 'GET', { query: `id=eq.${uid}&select=name` });
        const name = custs && custs[0] ? custs[0].name : 'Unknown';
        await db('pending_payments', 'POST', { body: { customer_id: uid, customer_name: name, amount: body.amount || 500, method: body.method || 'GCash', ref_number: (body.refNumber || '').substring(0, 50) } });
        return res.status(200).json({ success: true });
      }
    }

    // ---------- ADMIN ROUTES ----------
    if (session.type === 'a') {
      if (action === 'dashboard') {
        const [licenses, customers, devices, logs, payments, settings, pms, dls] = await Promise.all([
          db('licenses', 'GET', { query: 'select=*&order=created_at.desc' }),
          db('customers', 'GET', { query: 'select=id,name,email,phone,created_at&order=created_at.desc' }),
          db('devices', 'GET', { query: 'select=*&order=last_seen.desc' }),
          db('logs', 'GET', { query: 'select=*&order=timestamp.desc&limit=50' }),
          db('pending_payments', 'GET', { query: 'select=*&order=submitted_at.desc' }),
          db('site_settings', 'GET', { query: 'id=eq.1' }),
          db('payment_methods', 'GET', { query: 'select=*&order=sort_order' }),
          db('downloads', 'GET', { query: 'select=*&order=sort_order' }).catch(() => [])
        ]);
        return res.status(200).json({ licenses, customers, devices, logs, payments, settings: (settings && settings[0]) || {}, pms: pms || [], downloads: dls || [] });
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
        const k = genKey();
        await db('licenses', 'POST', { body: { key: k, type: 'permanent', status: 'inactive', customer_id: p.customer_id } });
        await log('payment_approved', k, null, `${p.method} P${p.amount} ${p.customer_name}`);
        return res.status(200).json({ success: true, key: k });
      }
      if (action === 'reject_payment') { await db('pending_payments', 'PATCH', { query: `id=eq.${body.paymentId}`, body: { status: 'rejected' } }); return res.status(200).json({ success: true }); }
      if (action === 'suspend') { await db('licenses', 'PATCH', { query: `key=eq.${encodeURIComponent(body.key)}`, body: { status: 'suspended' } }); await log('suspended', body.key, null, 'Admin'); return res.status(200).json({ success: true }); }
      if (action === 'admin_revoke') { await db('licenses', 'PATCH', { query: `key=eq.${encodeURIComponent(body.key)}`, body: { status: 'revoked', chip_id: null } }); await log('revoked', body.key, null, 'Admin'); return res.status(200).json({ success: true }); }
      if (action === 'reactivate') { await db('licenses', 'PATCH', { query: `key=eq.${encodeURIComponent(body.key)}`, body: { status: 'inactive' } }); await log('reactivated', body.key, null, 'Admin'); return res.status(200).json({ success: true }); }
      if (action === 'delete_license') { await db('licenses', 'DELETE', { query: `key=eq.${encodeURIComponent(body.key)}` }); await log('deleted', body.key, null, 'Admin'); return res.status(200).json({ success: true }); }
      if (action === 'bulk_delete') {
        const keys = body.keys || [];
        for (const k of keys) { await db('licenses', 'DELETE', { query: `key=eq.${encodeURIComponent(k)}` }); }
        await log('bulk_deleted', null, null, 'Deleted ' + keys.length);
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
    }

    return res.status(400).json({ error: 'Unknown action' });
  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
};
