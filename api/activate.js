const { supabase, logAction } = require('./_lib/db');

module.exports = async (req, res) => {
  // CORS headers for ESP32
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
      await logAction('activate_failed', key, chipId, ip, 'Invalid key');
      return res.status(404).json({ status: 'error', message: 'Invalid license key' });
    }

    const lic = licenses[0];

    // Check if revoked or suspended
    if (lic.status === 'revoked') {
      await logAction('activate_failed', key, chipId, ip, 'Key revoked');
      return res.status(403).json({ status: 'error', message: 'License has been revoked' });
    }
    if (lic.status === 'suspended') {
      await logAction('activate_failed', key, chipId, ip, 'Key suspended');
      return res.status(403).json({ status: 'error', message: 'License is suspended' });
    }

    // Check if already active on another device
    if (lic.status === 'active' && lic.chip_id && lic.chip_id !== chipId) {
      await logAction('activate_failed', key, chipId, ip, 'Already active on ' + lic.chip_id);
      return res.status(409).json({ status: 'error', message: 'License active on another device. Deactivate first.' });
    }

    // Check if already active on this device
    if (lic.status === 'active' && lic.chip_id === chipId) {
      await logAction('verify', key, chipId, ip, 'Already activated');
      return res.status(200).json({ status: 'active', message: 'Already activated on this device' });
    }

    // Activate: update license
    await supabase('licenses', 'PATCH', {
      query: `key=eq.${encodeURIComponent(key)}`,
      body: {
        status: 'active',
        chip_id: chipId,
        activated_at: new Date().toISOString()
      }
    });

    // Upsert device record
    try {
      const existingDevices = await supabase('devices', 'GET', {
        query: `chip_id=eq.${encodeURIComponent(chipId)}&select=id`
      });
      
      if (existingDevices && existingDevices.length > 0) {
        await supabase('devices', 'PATCH', {
          query: `chip_id=eq.${encodeURIComponent(chipId)}`,
          body: { firmware_version: firmware || '', last_seen: new Date().toISOString(), ip_address: ip, license_key: key }
        });
      } else {
        await supabase('devices', 'POST', {
          body: { chip_id: chipId, firmware_version: firmware || '', last_seen: new Date().toISOString(), ip_address: ip, license_key: key }
        });
      }
    } catch (e) {
      console.error('Device upsert error:', e);
    }

    await logAction('activate', key, chipId, ip, 'Activated successfully');
    return res.status(200).json({ status: 'active', message: 'License activated!' });

  } catch (error) {
    console.error('Activate error:', error);
    return res.status(500).json({ status: 'error', message: 'Server error' });
  }
};
