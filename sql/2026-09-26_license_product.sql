-- N&R SOLARTECH licensing - 26 Sep 2026
-- PRODUCT-SPECIFIC NR KEYS: which machine a key is for.
--   'kiosk'   = N&R Carwash Kiosk (tablet)
--   'carwash' = SmartCarwash hybrid (7-segment / LCD firmware)
--   NULL      = any product (every key made before today, and the other
--               machines: NR-CHARGER, Coin Changer, Phone Rental ...)
-- Safe to run more than once. Changes no existing key: they all stay NULL and
-- are locked to the product they are first activated on.
-- RUN THIS FIRST, then deploy api/index.js and public/index.html.

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS product TEXT;

ALTER TABLE licenses DROP CONSTRAINT IF EXISTS licenses_product_check;
ALTER TABLE licenses ADD CONSTRAINT licenses_product_check
  CHECK (product IS NULL OR product IN ('kiosk', 'carwash'));

-- check: how many keys per product (all NULL right after running this)
SELECT COALESCE(product, 'any (not set)') AS product, status, COUNT(*) AS keys
FROM licenses GROUP BY 1, 2 ORDER BY 1, 2;
