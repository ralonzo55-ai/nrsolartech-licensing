# N&R SOLARTECH - Licensing System Deployment Guide
# Step-by-step instructions

## STEP 1: Setup Supabase Database

1. Go to https://supabase.com/dashboard/projects
2. Click your "nrsolartech" project (or create one: New Project → name: nrsolartech → region: Singapore)
3. Wait for project to finish creating (green status)
4. In the LEFT sidebar, click the ICON that looks like a DATABASE (cylinder shape) labeled "SQL Editor"
5. Click "New query" (top right area)
6. You will see a blank text editor
7. Open the file "database.sql" from the deployment package
8. COPY ALL the contents of database.sql
9. PASTE it into the Supabase SQL Editor
10. Click the GREEN "Run" button (or press Ctrl+Enter)
11. You should see: "Success. No rows returned" - this means it worked!

## STEP 2: Get Your API Keys

1. In the LEFT sidebar, click the GEAR ICON at the bottom (Project Settings)
2. Click "API" in the left menu (under Configuration section)
3. You will see:
   - Project URL: https://xxxxx.supabase.co  ← COPY THIS
   - anon public key: eyJhbGciOi...           ← COPY THIS
4. Save both values - you need them for Step 4

## STEP 3: Deploy to Vercel

1. Go to https://vercel.com/dashboard
2. Click "Add New..." → "Project"
3. You will see "Import Git Repository" - IGNORE this
4. Scroll down and look for "Import Third-Party Git Repository" or
   look for a link that says "Upload" or "Deploy Template"
   
   EASIEST METHOD: Use Vercel CLI
   
   OR: Just drag and drop!
   a. Go to https://vercel.com/new
   b. Look for "Import" options
   c. If you see "Upload", click it and select the nrsolartech-licensing folder
   
   ALTERNATIVE METHOD (recommended):
   a. Go to https://github.com - create account if needed
   b. Create a new repository named "nrsolartech-licensing"
   c. Upload ALL files from the nrsolartech-licensing folder to GitHub
   d. Go back to Vercel → New Project → Import from GitHub
   e. Select the nrsolartech-licensing repository
   f. Click Deploy

## STEP 4: Add Environment Variables

IMPORTANT: Do this BEFORE or RIGHT AFTER deploying!

1. In Vercel, go to your project → Settings → Environment Variables
2. Add these TWO variables:

   Name: SUPABASE_URL
   Value: (paste your Project URL from Step 2)
   
   Name: SUPABASE_KEY  
   Value: (paste your anon public key from Step 2)

3. Click "Save" for each one
4. Go to Deployments → click "..." on latest deployment → "Redeploy"

## STEP 5: Test Your Website

1. After deploy completes, Vercel gives you a URL like:
   https://nrsolartech-licensing.vercel.app
   
2. Open that URL - you should see the landing page!
3. Test admin login:
   - Tap "N&R SOLARTECH" text 5 times fast → Developer Login appears
   - Email: admin@nrsolartech.com
   - Password: admin123
   
4. Test customer:
   - Click Register → create a test account
   - Login → you should see empty license list

## STEP 6: Change Admin Password

After first login, change the admin password:
1. Go to Supabase Dashboard → Table Editor (left sidebar, grid icon)
2. Click "admins" table
3. Click on the row with admin@nrsolartech.com
4. Change password_hash to your new password
5. Click Save

## STEP 7: Custom Domain (Optional, ~₱500-700/year)

1. Buy a domain from Namecheap, GoDaddy, or local registrar
2. In Vercel → Settings → Domains → Add your domain
3. Follow Vercel's instructions to point DNS

## FILES IN THIS PACKAGE

- database.sql          → Paste into Supabase SQL Editor (Step 1)
- vercel.json           → Vercel configuration (auto-detected)
- package.json          → Project metadata
- public/index.html     → Main website (landing + customer + admin)
- api/activate.js       → ESP32 calls this to activate license
- api/verify.js         → ESP32 calls this to verify license (every 24hr)
- api/admin.js          → Admin portal API
- api/customer.js       → Customer portal API  
- api/_lib/db.js        → Database helper (used by all APIs)
- DEPLOY_GUIDE.md       → This file

## TROUBLESHOOTING

"500 Internal Server Error" on API calls:
→ Check that SUPABASE_URL and SUPABASE_KEY are set in Vercel Environment Variables
→ Redeploy after adding them

"CORS error" in browser console:
→ This should not happen - all APIs have CORS headers. Try redeploying.

Website loads but shows "Loading..." forever:
→ The API is not connecting to Supabase. Check environment variables.

Admin login fails:
→ Make sure you ran the database.sql script in Step 1
→ Default: admin@nrsolartech.com / admin123
