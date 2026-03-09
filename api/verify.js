const { supabase, logAction } = require('./_lib/db');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  try {
    const { key, chipId, firmware } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.connection?.remoteAddress || '';

    if (!key || !chipId) {
      return res.status(400).json({ status: 'error', message: 'Missing key or chipId' });
    }

    // Find license
    const licenses = await supabase('licenses', 'GET', {
      query: `key=eq.${encodeURIComponent(key)}&select=*`
    });

    if (!licenses || licenses.length === 0) {
      return res.status(404).json({ status: 'invalid', message: 'License not found' });
    }

    const lic = licenses[0];

    // Update device last_seen
    try {
      await supabase('devices', 'PATCH', {
        query: `chip_id=eq.${encodeURIComponent(chipId)}`,
        body: { last_seen: new Date().toISOString(), ip_address: ip, firmware_version: firmware || '' }
      });
    } catch (e) { /* ignore */ }

    // Check status
    if (lic.status === 'active' && lic.chip_id === chipId) {
      await logAction('verify', key, chipId, ip, 'OK');
      return res.status(200).json({ status: 'active', message: 'License valid' });
    }

    if (lic.status === 'active' && lic.chip_id !== chipId) {
      await logAction('verify_failed', key, chipId, ip, 'Wrong device: ' + lic.chip_id);
      return res.status(403).json({ status: 'wrong_device', message: 'License active on different device' });
    }

    if (lic.status === 'suspended') {
      await logAction('verify_failed', key, chipId, ip, 'Suspended');
      return res.status(403).json({ status: 'suspended', message: 'License suspended' });
    }

    if (lic.status === 'revoked') {
      await logAction('verify_failed', key, chipId, ip, 'Revoked');
      return res.status(403).json({ status: 'revoked', message: 'License revoked' });
    }

    // Inactive
    return res.status(403).json({ status: 'inactive', message: 'License not activated' });

  } catch (error) {
    console.error('Verify error:', error);
    return res.status(500).json({ status: 'error', message: 'Server error' });
  }
};
