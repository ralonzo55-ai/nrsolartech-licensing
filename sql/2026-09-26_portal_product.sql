-- N&R SOLARTECH licensing - 26 Sep 2026 (part 2)
-- THE CUSTOMER PORTAL SELLS PRODUCT-SPECIFIC KEYS.
--   products.license_product   which machine keys sold with this product work
--                              on: 'carwash' (SmartCarwash hybrid), 'kiosk'
--                              (Carwash Kiosk) or NULL (any product)
--   pending_payments.product   the machine the customer paid for; approving the
--   pending_payments.product_name  payment creates keys for that machine
-- Safe to run more than once. Changes no existing row.
-- After running: open the admin page > Products and choose, for each product,
-- "Keys sold with this product work on".

ALTER TABLE products ADD COLUMN IF NOT EXISTS license_product TEXT;
ALTER TABLE products DROP CONSTRAINT IF EXISTS products_license_product_check;
ALTER TABLE products ADD CONSTRAINT products_license_product_check
  CHECK (license_product IS NULL OR license_product IN ('kiosk', 'carwash'));

ALTER TABLE pending_payments ADD COLUMN IF NOT EXISTS product TEXT;
ALTER TABLE pending_payments ADD COLUMN IF NOT EXISTS product_name TEXT;
ALTER TABLE pending_payments DROP CONSTRAINT IF EXISTS pending_payments_product_check;
ALTER TABLE pending_payments ADD CONSTRAINT pending_payments_product_check
  CHECK (product IS NULL OR product IN ('kiosk', 'carwash'));

-- check: your products and which machine their keys will work on
SELECT name, price, COALESCE(license_product, 'any (not set)') AS keys_work_on
FROM products ORDER BY sort_order;
