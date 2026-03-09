// Supabase client helper for API routes
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://sdviemivuftnsytmnqaq.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNkdmllbWl2dWZ0bnN5dG1ucWFxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzMwMzAwMTcsImV4cCI6MjA4ODYwNjAxN30.iRSuCtEullsSaV_1hYAqPj_sywXdy-4U3WfHjIYCB4U';

async function supabase(table, method, options = {}) {
  let url = `${SUPABASE_URL}/rest/v1/${table}`;
  const headers = {
    'apikey': SUPABASE_KEY,
    'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Content-Type': 'application/json',
    'Prefer': method === 'POST' ? 'return=representation' : 'return=minimal'
  };

  if (options.select) headers['Accept'] = 'application/json';
  if (options.query) url += `?${options.query}`;
  if (options.single) headers['Accept'] = 'application/vnd.pgrst.object+json';

  const fetchOptions = { method: method || 'GET', headers };
  if (options.body) fetchOptions.body = JSON.stringify(options.body);

  const res = await fetch(url, fetchOptions);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Supabase error: ${res.status} ${text}`);
  }
  
  const contentType = res.headers.get('content-type');
  if (contentType && contentType.includes('json')) {
    return res.json();
  }
  return null;
}

// Log an action
async function logAction(action, licenseKey, chipId, ip, details) {
  try {
    await supabase('logs', 'POST', {
      body: { action, license_key: licenseKey, chip_id: chipId, ip_address: ip || '', details: details || '' }
    });
  } catch (e) {
    console.error('Log error:', e);
  }
}

// Generate license key: NR-XXXX-XXXX-XXXX
function generateKey() {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const seg = () => Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  return `NR-${seg()}-${seg()}-${seg()}`;
}

module.exports = { supabase, logAction, generateKey };
