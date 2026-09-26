-- N&R SOLARTECH licensing - 26 Sep 2026 (part 3)
-- A THIRD PRODUCT: THE PAYMENT KIOSK ('paykiosk').
-- Widens the three product checks to allow it. Safe to run more than once;
-- changes no existing row.

ALTER TABLE licenses DROP CONSTRAINT IF EXISTS licenses_product_check;
ALTER TABLE licenses ADD CONSTRAINT licenses_product_check
  CHECK (product IS NULL OR product IN ('kiosk', 'carwash', 'paykiosk'));

ALTER TABLE products DROP CONSTRAINT IF EXISTS products_license_product_check;
ALTER TABLE products ADD CONSTRAINT products_license_product_check
  CHECK (license_product IS NULL OR license_product IN ('kiosk', 'carwash', 'paykiosk'));

ALTER TABLE pending_payments DROP CONSTRAINT IF EXISTS pending_payments_product_check;
ALTER TABLE pending_payments ADD CONSTRAINT pending_payments_product_check
  CHECK (product IS NULL OR product IN ('kiosk', 'carwash', 'paykiosk'));

-- check: the three rules now allow 'paykiosk' (expect 3 rows)
SELECT conname, pg_get_constraintdef(oid) AS rule
FROM pg_constraint
WHERE conname IN ('licenses_product_check', 'products_license_product_check', 'pending_payments_product_check');
