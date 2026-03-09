-- ============================================================================
-- N&R SOLARTECH - ESP32 4IN1 CarWash Licensing System
-- Supabase Database Setup Script
-- Copy and paste this ENTIRE script into Supabase SQL Editor
-- ============================================================================

-- 1. CUSTOMERS TABLE
CREATE TABLE IF NOT EXISTS customers (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT DEFAULT '',
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. LICENSES TABLE
CREATE TABLE IF NOT EXISTS licenses (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  key TEXT UNIQUE NOT NULL,
  type TEXT DEFAULT 'permanent' CHECK (type IN ('permanent', 'temporary')),
  status TEXT DEFAULT 'inactive' CHECK (status IN ('active', 'inactive', 'suspended', 'revoked')),
  chip_id TEXT,
  customer_id UUID REFERENCES customers(id),
  activated_at TIMESTAMP WITH TIME ZONE,
  max_transfers INTEGER DEFAULT 5,
  transfer_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. DEVICES TABLE
CREATE TABLE IF NOT EXISTS devices (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  chip_id TEXT UNIQUE NOT NULL,
  firmware_version TEXT DEFAULT '',
  last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  ip_address TEXT DEFAULT '',
  license_key TEXT REFERENCES licenses(key)
);

-- 4. ACTIVITY LOGS TABLE
CREATE TABLE IF NOT EXISTS logs (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  action TEXT NOT NULL,
  license_key TEXT,
  chip_id TEXT,
  ip_address TEXT DEFAULT '',
  details TEXT DEFAULT ''
);

-- 5. PENDING PAYMENTS TABLE
CREATE TABLE IF NOT EXISTS pending_payments (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  customer_id UUID REFERENCES customers(id),
  customer_name TEXT NOT NULL,
  amount INTEGER DEFAULT 500,
  method TEXT DEFAULT 'GCash',
  ref_number TEXT DEFAULT '',
  submitted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected'))
);

-- 6. SITE SETTINGS TABLE (single row)
CREATE TABLE IF NOT EXISTS site_settings (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  lcd_firmware TEXT DEFAULT 'SmartCarwash_v14_LCD.bin',
  seg_firmware TEXT DEFAULT 'SmartCarwash_v14_7seg.bin',
  lcd_version TEXT DEFAULT 'v14-LCD',
  seg_version TEXT DEFAULT 'v14-SEG',
  flash_instructions TEXT DEFAULT 'Board: ESP32 Dev Module\nPartition: Huge APP (3MB No OTA)\n\n1. Install Arduino IDE\n2. Add ESP32 board URL\n3. Install ESP32 board\n4. Select ESP32 Dev Module\n5. Upload firmware',
  wiring_guide TEXT DEFAULT 'COIN -> GPIO 19\nBUTTONS -> GPIO 25,26,27,14\nRELAYS -> GPIO 16,17,18,23\nBUZZER -> GPIO 5\nSENSOR -> GPIO 15\nLCD: SDA->21, SCL->22',
  announcement TEXT DEFAULT '',
  price INTEGER DEFAULT 500
);

-- 7. ADMIN USERS TABLE
CREATE TABLE IF NOT EXISTS admins (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- INSERT DEFAULT DATA
-- ============================================================================

-- Default site settings (single row)
INSERT INTO site_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- Default admin account (email: admin@nrsolartech.com, password: admin123)
-- Password is hashed with simple method - you should change this after first login
INSERT INTO admins (email, password_hash)
VALUES ('admin@nrsolartech.com', 'admin123')
ON CONFLICT (email) DO NOTHING;

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

-- Enable RLS on all tables
ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE licenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE pending_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE site_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE admins ENABLE ROW LEVEL SECURITY;

-- Allow anonymous access for API operations (ESP32 devices + website)
-- In production, you'd use proper JWT auth, but for simplicity:
CREATE POLICY "Allow all operations on customers" ON customers FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations on licenses" ON licenses FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations on devices" ON devices FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations on logs" ON logs FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations on pending_payments" ON pending_payments FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations on site_settings" ON site_settings FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations on admins" ON admins FOR ALL USING (true) WITH CHECK (true);

-- ============================================================================
-- INDEXES for faster queries
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(key);
CREATE INDEX IF NOT EXISTS idx_licenses_chip ON licenses(chip_id);
CREATE INDEX IF NOT EXISTS idx_licenses_customer ON licenses(customer_id);
CREATE INDEX IF NOT EXISTS idx_devices_chip ON devices(chip_id);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_license ON logs(license_key);
CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(email);

-- ============================================================================
-- DONE! You should see "Success. No rows returned" message.
-- ============================================================================
