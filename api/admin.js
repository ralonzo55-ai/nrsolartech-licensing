const { supabase, logAction, generateKey } = require('./_lib/db');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  try {
    const { action, email, password, ...data } = req.body;

    // Admin login
    if (action === 'login') {
      const admins = await supabase('admins', 'GET', {
        query: `email=eq.${encodeURIComponent(email)}&password_hash=eq.${encodeURIComponent(password)}&select=*`
      });
      if (!admins || admins.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      return res.status(200).json({ success: true, admin: { email: admins[0].email } });
    }

    // Get dashboard data
    if (action === 'dashboard') {
      const [licenses, customers, devices, logs, payments, settings] = await Promise.all([
        supabase('licenses', 'GET', { query: 'select=*&order=created_at.desc' }),
        supabase('customers', 'GET', { query: 'select=*&order=created_at.desc' }),
        supabase('devices', 'GET', { query: 'select=*&order=last_seen.desc' }),
        supabase('logs', 'GET', { query: 'select=*&order=timestamp.desc&limit=50' }),
        supabase('pending_payments', 'GET', { query: 'select=*&order=submitted_at.desc' }),
        supabase('site_settings', 'GET', { query: 'id=eq.1', single: true }),
      ]);
      return res.status(200).json({ licenses, customers, devices, logs, payments, settings });
    }

    // Create license(s)
    if (action === 'create_license') {
      const count = data.count || 1;
      const keys = [];
      for (let i = 0; i < count; i++) {
        const key = generateKey();
        await supabase('licenses', 'POST', { body: { key, type: 'permanent', status: 'inactive' } });
        await logAction('created', key, null, '', 'Admin created');
        keys.push(key);
      }
      return res.status(200).json({ success: true, keys });
    }

    // Approve payment
    if (action === 'approve_payment') {
      const payments = await supabase('pending_payments', 'GET', {
        query: `id=eq.${data.paymentId}&select=*`, single: true
      });
      if (!payments) return res.status(404).json({ error: 'Payment not found' });

      await supabase('pending_payments', 'PATCH', {
        query: `id=eq.${data.paymentId}`,
        body: { status: 'approved' }
      });

      const key = generateKey();
      await supabase('licenses', 'POST', {
        body: { key, type: 'permanent', status: 'inactive', customer_id: payments.customer_id }
      });
      await logAction('payment_approved', key, null, '', `${payments.method} P${payments.amount} ${payments.customer_name}`);
      return res.status(200).json({ success: true, key });
    }

    // Reject payment
    if (action === 'reject_payment') {
      await supabase('pending_payments', 'PATCH', {
        query: `id=eq.${data.paymentId}`,
        body: { status: 'rejected' }
      });
      return res.status(200).json({ success: true });
    }

    // Suspend license
    if (action === 'suspend') {
      await supabase('licenses', 'PATCH', {
        query: `key=eq.${encodeURIComponent(data.key)}`,
        body: { status: 'suspended' }
      });
      await logAction('suspended', data.key, null, '', 'Admin');
      return res.status(200).json({ success: true });
    }

    // Revoke license
    if (action === 'revoke') {
      await supabase('licenses', 'PATCH', {
        query: `key=eq.${encodeURIComponent(data.key)}`,
        body: { status: 'revoked', chip_id: null }
      });
      await logAction('revoked', data.key, null, '', 'Admin');
      return res.status(200).json({ success: true });
    }

    // Reactivate license
    if (action === 'reactivate') {
      await supabase('licenses', 'PATCH', {
        query: `key=eq.${encodeURIComponent(data.key)}`,
        body: { status: 'inactive' }
      });
      await logAction('reactivated', data.key, null, '', 'Admin');
      return res.status(200).json({ success: true });
    }

    // Clear logs
    if (action === 'clear_logs') {
      await supabase('logs', 'DELETE', { query: 'id=neq.00000000-0000-0000-0000-000000000000' });
      return res.status(200).json({ success: true });
    }

    // Update site settings
    if (action === 'update_settings') {
      await supabase('site_settings', 'PATCH', {
        query: 'id=eq.1',
        body: data.settings
      });
      return res.status(200).json({ success: true });
    }

    return res.status(400).json({ error: 'Unknown action' });

  } catch (error) {
    console.error('Admin error:', error);
    return res.status(500).json({ error: 'Server error: ' + error.message });
  }
};
