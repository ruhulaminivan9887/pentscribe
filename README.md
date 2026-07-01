# PentScribe v2

Professional pentest report writer. Real frontend + real backend + real exports + real payments.

## What changed from v1
- New visual identity: dark glassmorphism/neon (not the old flat "Clean SaaS" look)
- CVSS v3.1 calculator is now mathematically exact (verified against FIRST.org reference vectors: 9.8 and 10.0)
- CVSS v4.0 toggle added — labeled "beta/approximate" in the UI because the real v4.0 spec uses a 2,450-row lookup table that can't be reasonably hand-verified; flagging this honestly beats silently guessing
- Word export now runs server-side (`docx` library) instead of being a locked "Pro" teaser
- AI Draft buttons on Executive Summary, Description, and Remediation — calls Claude via your own `ANTHROPIC_API_KEY`
- Save/Load — reports persist as JSON on the server with a shareable Project ID
- Live severity donut chart + severity distribution bar
- Freemium limiter (3 free exports/day per IP) with a real Stripe Checkout paywall, not just a modal

## Run locally
```bash
npm install
cp .env.example .env   # fill in ANTHROPIC_API_KEY / Stripe keys if you want those features live
npm start
```
Visit http://localhost:3000

Without any keys set, the report builder, CVSS calculator, live preview, and Markdown/Word export all work fully. Only "AI Draft" and "Upgrade to Pro" need the keys below.

## Deploy to Render (or Railway/Fly/any Node host)
```bash
git init
git add .
git commit -m "PentScribe v2"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/pentscribe.git
git push -u origin main
```
On Render: **New → Web Service → connect repo**
- Build command: `npm install`
- Start command: `npm start`
- Add environment variables from `.env.example` in the dashboard

## Getting paid — Stripe setup (money → your bank account)
1. Create a Stripe account at stripe.com and finish identity/bank verification
2. Products → **+ Add Product** → name "PentScribe Pro" → $9.00/month recurring → save
3. Copy the **Price ID** (`price_...`) into `STRIPE_PRICE_ID`
4. Developers → API keys → copy the **Secret key** into `STRIPE_SECRET_KEY`
5. Developers → Webhooks → **Add endpoint** → URL: `https://yourdomain.com/api/stripe-webhook` → event: `checkout.session.completed` → copy the **Signing secret** into `STRIPE_WEBHOOK_SECRET`
6. Redeploy with those three variables set

Once live: a customer clicks "Upgrade Now" → Stripe Checkout opens → they pay → Stripe settles the money into your connected bank account on your payout schedule (default: every 2 business days) → the webhook marks their session as Pro in this app.

**Important limitation to know:** the in-memory "who is Pro" list (`proUsers` in `server.js`) resets whenever the server restarts. That's fine for validating the full payment flow end-to-end, but for a real paying customer base you'll want to swap that `Set` for a real database (Postgres/SQLite) so licenses survive deploys. Say the word and I'll wire that in.

## Desktop app (Electron)
This sandbox can't download the Electron binary (network is restricted to package registries), so build the desktop wrapper on your own machine:
```bash
npm install --save-dev electron
```
Create `electron-main.js` in the project root:
```js
const { app, BrowserWindow } = require('electron');
require('./server.js'); // starts the same Express server on PORT (default 3000)

function createWindow() {
  const win = new BrowserWindow({ width: 1440, height: 900, backgroundColor: '#050508' });
  win.loadURL('http://localhost:3000');
}
app.whenReady().then(createWindow);
```
Then run `npx electron .` to launch it as a desktop window, or use `electron-builder` to produce a real installable `.exe`/`.dmg`.

## Project structure
```
pentscribe/
├── server.js              # Express API: exports, AI assist, save/load, Stripe
├── package.json
├── .env.example
└── public/
    ├── index.html
    ├── css/style.css       # dark glassmorphism/neon design system
    └── js/
        ├── cvss.js         # CVSS v3.1 (exact) + v4.0 (approximate) calculators
        └── app.js          # state, rendering, exports, save/load, paywall
```
