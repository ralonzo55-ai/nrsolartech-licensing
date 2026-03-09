const { supabase, logAction } = require('./_lib/db');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  try {
    const { action, ...data } = req.body;

    // Register
    if (action === 'register') {
      if (!data.name || !data.email || !data.password) {
        return res.status(400).json({ error: 'All fields required' });
      }
      // Check if email exists
      const existing = await supabase('customers', 'GET', {
        query: `email=eq.${encodeURIComponent(data.email)}&select=id`
      });
      if (existing && existing.length > 0) {
        return res.status(409).json({ error: 'Email already registered' });
      }
      const result = await supabase('customers', 'POST', {
        body: { name: data.name, phone: data.phone || '', email: data.email, password_hash: data.password }
      });
      return res.status(200).json({ success: true, customer: result[0] });
    }

    // Login
    if (action === 'login') {
      const customers = await supabase('customers', 'GET', {
        query: `email=eq.${encodeURIComponent(data.email)}&password_hash=eq.${encodeURIComponent(data.password)}&select=*`
      });
      if (!customers || customers.length === 0) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }
      return res.status(200).json({ success: true, customer: customers[0] });
    }

    // Get my licenses
    if (action === 'my_licenses') {
      const licenses = await supabase('licenses', 'GET', {
        query: `customer_id=eq.${data.customerId}&select=*`
      });
      return res.status(200).json({ licenses: licenses || [] });
    }

    // Get my logs
    if (action === 'my_logs') {
      // Get customer's license keys first
      const licenses = await supabase('licenses', 'GET', {
        query: `customer_id=eq.${data.customerId}&select=key`
      });
      const keys = (licenses || []).map(l => l.key);
      if (keys.length === 0) return res.status(200).json({ logs: [] });

      // Get logs for those keys
      const allLogs = [];
      for (const key of keys) {
        const logs = await supabase('logs', 'GET', {
          query: `license_key=eq.${encodeURIComponent(key)}&select=*&order=timestamp.desc&limit=20`
        });
        if (logs) allLogs.push(...logs);
      }
      allLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      return res.status(200).json({ logs: allLogs.slice(0, 30) });
    }

    // Claim license
    if (action === 'claim') {
      const key = (data.key || '').toUpperCase().trim();
      const licenses = await supabase('licenses', 'GET', {
        query: `key=eq.${encodeURIComponent(key)}&select=*`
      });
      if (!licenses || licenses.length === 0) {
        return res.status(404).json({ error: 'Invalid license key' });
      }
      const lic = licenses[0];
      if (lic.customer_id && lic.customer_id !== data.customerId) {
        return res.status(403).json({ error: 'License belongs to another customer' });
      }
      if (lic.customer_id === data.customerId) {
        return res.status(400).json({ error: 'You already own this license' });
      }
      await supabase('licenses', 'PATCH', {
        query: `key=eq.${encodeURIComponent(key)}`,
        body: { customer_id: data.customerId }
      });
      await logAction('claimed', key, null, '', 'Claimed by customer');
      return res.status(200).json({ success: true });
    }

    // Transfer (deactivate for transfer) - requires chip ID confirmation
    if (action === 'transfer') {
      const licenses = await supabase('licenses', 'GET', {
        query: `key=eq.${encodeURIComponent(data.key)}&select=*`, single: true
      });
      if (!licenses) return res.status(404).json({ error: 'License not found' });
      if (licenses.transfer_count >= licenses.max_transfers) {
        return res.status(403).json({ error: 'Transfer limit reached. Contact support.' });
      }
      // Chip ID confirmation required
      if (!data.confirmChipId || data.confirmChipId.toUpperCase().trim() !== (licenses.chip_id || '').toUpperCase().trim()) {
        return res.status(403).json({ error: 'Chip ID does not match. Check your device ID and try again.' });
      }
      const oldChip = licenses.chip_id;
      await supabase('licenses', 'PATCH', {
        query: `key=eq.${encodeURIComponent(data.key)}`,
        body: { status: 'inactive', chip_id: null, activated_at: null, transfer_count: licenses.transfer_count + 1 }
      });
      if (oldChip) {
        try { await supabase('devices', 'DELETE', { query: `chip_id=eq.${encodeURIComponent(oldChip)}` }); } catch(e) {}
      }
      await logAction('transfer', data.key, oldChip, '', 'Transfer #' + (licenses.transfer_count + 1) + ' confirmed with chip ID');
      return res.status(200).json({ success: true });
    }

    // Revoke (customer self-revoke) - requires chip ID confirmation
    if (action === 'revoke') {
      const licenses = await supabase('licenses', 'GET', {
        query: `key=eq.${encodeURIComponent(data.key)}&select=*`, single: true
      });
      if (!licenses) return res.status(404).json({ error: 'License not found' });
      // Chip ID confirmation required
      if (!data.confirmChipId || data.confirmChipId.toUpperCase().trim() !== (licenses.chip_id || '').toUpperCase().trim()) {
        return res.status(403).json({ error: 'Chip ID does not match. Check your device ID and try again.' });
      }
      const oldChip = licenses.chip_id;
      await supabase('licenses', 'PATCH', {
        query: `key=eq.${encodeURIComponent(data.key)}`,
        body: { status: 'inactive', chip_id: null, activated_at: null }
      });
      if (oldChip) {
        try { await supabase('devices', 'DELETE', { query: `chip_id=eq.${encodeURIComponent(oldChip)}` }); } catch(e) {}
      }
      await logAction('revoke', data.key, oldChip, '', 'Customer revoked with chip ID confirmation');
      return res.status(200).json({ success: true });
    }

    // Submit payment
    if (action === 'submit_payment') {
      await supabase('pending_payments', 'POST', {
        body: {
          customer_id: data.customerId,
          customer_name: data.customerName,
          amount: data.amount || 500,
          method: data.method || 'GCash',
          ref_number: data.refNumber || ''
        }
      });
      return res.status(200).json({ success: true });
    }

    // Get site settings (public)
    if (action === 'get_settings') {
      const settings = await supabase('site_settings', 'GET', {
        query: 'id=eq.1', single: true
      });
      return res.status(200).json({ settings });
    }

    return res.status(400).json({ error: 'Unknown action' });

  } catch (error) {
    console.error('Customer error:', error);
    return res.status(500).json({ error: 'Server error: ' + error.message });
  }
};
