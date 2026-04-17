// Ribbon Reflector — backend server
// Run: npm install && npm run seed && npm start
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const PORT = process.env.PORT || 3001;
const MEMBERSHIP_CENTS = 1000; // $10.00

// ===== DB SETUP =====
// Use the mounted persistent disk in production; fall back to local file for dev.
// DB_PATH env var lets us override, but sane defaults: /var/data/data.db on Render (persistent disk),
// ./data.db locally.
const DB_DIR = fs.existsSync('/var/data') ? '/var/data' : __dirname;
const db = new Database(path.join(DB_DIR, 'data.db'));
console.log('[db] Using SQLite file at', path.join(DB_DIR, 'data.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ===== ONE-TIME MIGRATION: swap-mode offers → cash-mode offers =====
// The old `offers` table has `offered_listing_id NOT NULL` and no `amount_cents` column.
// Detect the old shape and drop the table so schema.sql recreates it below.
// Safe to leave this block in place after migration — it's a no-op on the new shape.
// REMOVE this block after confirming migration has run on all environments.
try {
  const cols = db.prepare("PRAGMA table_info(offers)").all();
  const hasOldShape = cols.some(c => c.name === 'offered_listing_id');
  const hasNewShape = cols.some(c => c.name === 'amount_cents');
  if (hasOldShape && !hasNewShape) {
    console.log('[migration] Dropping old swap-mode offers table. Existing offer rows will be lost.');
    db.exec('DROP TABLE IF EXISTS offers;');
  }
} catch (e) {
  console.error('[migration] offers table check failed:', e.message);
}

// ===== ONE-TIME MIGRATION: swap-mode trades → cash-mode trades =====
// The old `trades` table has `user_a_id`/`user_b_id`/`listing_a_id`/`listing_b_id` etc.
// Detect and drop so schema.sql recreates it with buyer/seller shape.
// REMOVE this block after confirming migration has run on all environments.
try {
  const cols = db.prepare("PRAGMA table_info(trades)").all();
  const hasOldShape = cols.some(c => c.name === 'user_a_id');
  const hasNewShape = cols.some(c => c.name === 'buyer_id');
  if (hasOldShape && !hasNewShape) {
    console.log('[migration] Dropping old swap-mode trades table. Existing trade rows will be lost.');
    db.exec('DROP TABLE IF EXISTS trades;');
  }
} catch (e) {
  console.error('[migration] trades table check failed:', e.message);
}

const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
db.exec(schema);
// ===== PROFILE COLUMN MIGRATION (Step 8a) =====
// SQLite has no ADD COLUMN IF NOT EXISTS, so introspect first and add what's missing.
{
  const have = new Set(db.prepare("PRAGMA table_info(users)").all().map(c => c.name));
  for (const [col, type] of [['avatar_data_url','TEXT'],['link','TEXT'],['city','TEXT'],['region','TEXT']]) {
    if (!have.has(col)) {
      console.log('[migration] users: adding column', col);
      db.exec(`ALTER TABLE users ADD COLUMN ${col} ${type}`);
    }
  }
}
// ===== EMAIL VERIFICATION COLUMN MIGRATION (Step 9a) =====
{
  const have = new Set(db.prepare("PRAGMA table_info(users)").all().map(c => c.name));
  for (const [col, type] of [
    ['email_verified', 'INTEGER NOT NULL DEFAULT 0'],
    ['email_verification_token', 'TEXT'],
    ['email_verification_sent_at', 'TIMESTAMP'],
  ]) {
    if (!have.has(col)) {
      console.log('[migration] users: adding column', col);
      db.exec(`ALTER TABLE users ADD COLUMN ${col} ${type}`);
    }
  }
}
// ===== PASSWORD RESET COLUMN MIGRATION (Step 9b) =====
{
  const have = new Set(db.prepare("PRAGMA table_info(users)").all().map(c => c.name));
  for (const [col, type] of [
    ['password_reset_token', 'TEXT'],
    ['password_reset_expires_at', 'TIMESTAMP'],
  ]) {
    if (!have.has(col)) {
      console.log('[migration] users: adding column', col);
      db.exec(`ALTER TABLE users ADD COLUMN ${col} ${type}`);
    }
  }
}
// ===== STRIPE CONNECT COLUMN MIGRATION (Phase 1) =====
{
  const have = new Set(db.prepare("PRAGMA table_info(users)").all().map(c => c.name));
  for (const [col, type] of [
    ['stripe_account_id', 'TEXT'],
    ['stripe_account_status', "TEXT NOT NULL DEFAULT 'none'"],
  ]) {
    if (!have.has(col)) {
      console.log('[migration] users: adding column', col);
      db.exec(`ALTER TABLE users ADD COLUMN ${col} ${type}`);
    }
  }
}
// ===== PAYMENT INTENT COLUMN MIGRATION (Phase 2) =====
// payment_status lifecycle:
//   'pending'  → PI authorized, buyer hasn't paid yet
//   'paid'     → PI captured, funds held by platform
//   'failed'   → card declined / auth failed
//   'canceled' → buyer canceled or window expired
{
  const have = new Set(db.prepare("PRAGMA table_info(trades)").all().map(c => c.name));
  for (const [col, type] of [
    ['payment_intent_id', 'TEXT'],
    ['payment_status', "TEXT NOT NULL DEFAULT 'pending'"],
    ['payment_window_expires_at', 'TIMESTAMP'],
    ['payment_client_secret', 'TEXT'],
  ]) {
    if (!have.has(col)) {
      console.log('[migration] trades: adding column', col);
      db.exec(`ALTER TABLE trades ADD COLUMN ${col} ${type}`);
    }
  }
}
// ===== TRANSFER COLUMN MIGRATION (Phase 3) =====
{
  const have = new Set(db.prepare("PRAGMA table_info(trades)").all().map(c => c.name));
  if (!have.has('transfer_id')) {
    console.log('[migration] trades: adding column transfer_id');
    db.exec(`ALTER TABLE trades ADD COLUMN transfer_id TEXT`);
  }
}
// ===== APP =====
const app = express();
// Stripe webhook needs the raw body for signature verification — must be registered
// BEFORE express.json() parses it. All other routes use parsed JSON as usual.
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!STRIPE_WEBHOOK_SECRET || !stripe) return res.status(503).send('webhook not configured');
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    console.error('[webhook] signature verification failed:', e.message);
    return res.status(400).send('invalid signature');
  }
  console.log(`[webhook] ${event.type} id=${event.id}`);
  try {
    switch (event.type) {
      case 'account.updated': {
        const acct = event.data.object;
        const status = deriveStripeStatus(acct);
        db.prepare('UPDATE users SET stripe_account_status=? WHERE stripe_account_id=?').run(status, acct.id);
        console.log(`[webhook] account ${acct.id} → ${status}`);
        break;
      }
      case 'charge.dispute.created': {
        const dispute = event.data.object;
        const pi_id = dispute.payment_intent;
        if (pi_id) {
          const trade = db.prepare('SELECT * FROM trades WHERE payment_intent_id=?').get(pi_id);
          if (trade && trade.status === 'active') {
            db.prepare(`UPDATE trades SET status='disputed' WHERE id=?`).run(trade.id);
            notify(trade.buyer_id,  '⚠️', `Card dispute opened on trade #${trade.id}. Escrow paused.`, 'wallet');
            notify(trade.seller_id, '⚠️', `Card dispute opened on trade #${trade.id}. Escrow paused.`, 'wallet');
            console.log(`[webhook] trade ${trade.id} auto-disputed from charge dispute`);
          }
        }
        break;
      }
      case 'payment_intent.payment_failed': {
        const pi = event.data.object;
        const trade = db.prepare('SELECT * FROM trades WHERE payment_intent_id=?').get(pi.id);
        if (trade && trade.payment_status === 'pending') {
          db.prepare(`UPDATE trades SET payment_status='failed' WHERE id=?`).run(trade.id);
          console.log(`[webhook] trade ${trade.id} payment failed`);
        }
        break;
      }
      // payment_intent.succeeded, transfer.created, charge.refunded — logged for observability
      default:
        break;
    }
  } catch (e) {
    console.error('[webhook] handler error:', e.message);
  }
  res.json({ received: true });
});

app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());

// Rate limiting — generous for beta; tighten later.
const rateLimit = require('express-rate-limit');
app.use('/api/', rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60,             // 60 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too many requests — please slow down' },
}));
// Tighter limit on auth endpoints to prevent brute force.
app.use('/api/auth/', rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15,                   // 15 attempts per 15 min per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too many attempts — try again in a few minutes' },
}));

const ALLOWED_ORIGINS = [
  'https://ribbonreflector.com',
  'https://www.ribbonreflector.com',
  'https://ribbon-reflector-frontend.vercel.app',
];
app.use(cors({
  origin: (origin, cb) => {
    // Allow same-origin/server-to-server (no origin header) and the production frontend.
    // In development, also allow localhost.
    if (!origin || ALLOWED_ORIGINS.includes(origin)
      || /^https:\/\/ribbon-reflector-frontend.*\.vercel\.app$/.test(origin)
      || /^http:\/\/localhost(:\d+)?$/.test(origin)) {
      return cb(null, true);
    }
    cb(new Error('Not allowed by CORS: ' + origin));
  },
  credentials: true,
}));

// ===== MOCK STRIPE =====
// In production, replace with real Stripe SDK calls.
// Never put stripe.secret_key in frontend code.
function mockStripeCharge({ userId, amountCents, description }) {
  const id = 'ch_mock_' + Math.random().toString(36).slice(2, 12);
  console.log(`[stripe-mock] charge ${id} · user ${userId} · $${(amountCents/100).toFixed(2)} · ${description}`);
  return { id, status: 'succeeded', amount: amountCents };
}
function mockStripeRefund(chargeId, amountCents) {
  const id = 're_mock_' + Math.random().toString(36).slice(2, 12);
  console.log(`[stripe-mock] refund ${id} · charge ${chargeId} · $${(amountCents/100).toFixed(2)}`);
  return { id, status: 'succeeded' };
}

// ===== AUTH MIDDLEWARE =====
function authRequired(req, res, next) {
  // Prefer Authorization header (works cross-origin, avoids cookie issues)
  const authHeader = req.headers.authorization || '';
  const headerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const token = headerToken || req.cookies.rr_token;
  if (!token) return res.status(401).json({ error: 'not authenticated' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id, handle, email, is_member, member_until, bio, avatar_data_url, link, city, region, email_verified, email_verification_sent_at, stripe_account_id, stripe_account_status FROM users WHERE id = ?').get(payload.userId);
    if (!user) return res.status(401).json({ error: 'user not found' });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid token' });
  }
}
function memberRequired(req, res, next) {
  if (!req.user.is_member) return res.status(402).json({ error: 'membership required', upgrade: '/api/checkout/membership' });
  next();
}
function makeToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
}

// ===== EMAIL (Step 9a) =====
const crypto = require('crypto');
const { Resend } = require('resend');
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const FROM_EMAIL = process.env.FROM_EMAIL || 'Ribbon Reflector <team@ribbonreflector.com>';
const FRONTEND_URL = (process.env.FRONTEND_URL || 'https://ribbon-reflector-frontend.vercel.app').replace(/\/$/, '');
const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;
if (!resend) console.warn('[email] RESEND_API_KEY not set — emails will be logged to console only.');

async function sendEmail({ to, subject, html, text }) {
  if (!resend) {
    console.log('[email DEV MODE]');
    console.log('  to:', to);
    console.log('  subject:', subject);
    console.log('  text:', text);
    return { dev: true };
  }
  try {
    return await resend.emails.send({ from: FROM_EMAIL, to, subject, html, text });
  } catch (e) {
    console.error('[email] send failed:', e.message);
    throw e;
  }
}

function sendVerificationEmail(user, token) {
  const url = `${FRONTEND_URL}/?verify=${encodeURIComponent(token)}`;
  return sendEmail({
    to: user.email,
    subject: 'Verify your email — Ribbon Reflector',
    text: `Hi ${user.handle},\n\nConfirm your email to start trading tickets on Ribbon Reflector:\n\n${url}\n\nThis link expires in 24 hours. If you didn't sign up, ignore this email.\n\n— Ribbon Reflector`,
    html: `<div style="font-family:-apple-system,Segoe UI,sans-serif;max-width:520px;margin:0 auto;padding:24px;color:#1a1a1a">
      <h2 style="margin:0 0 14px">Welcome to Ribbon Reflector</h2>
      <p>Hi ${user.handle},</p>
      <p>Confirm your email address to start trading tickets with other fans.</p>
      <p style="margin:24px 0"><a href="${url}" style="display:inline-block;background:#1a1a1a;color:#fff;padding:12px 22px;border-radius:8px;text-decoration:none;font-weight:600">Verify email</a></p>
      <p style="color:#666;font-size:13px">Or paste this link into your browser:<br><span style="color:#999">${url}</span></p>
      <p style="color:#666;font-size:13px;margin-top:20px">This link expires in 24 hours. If you didn't sign up, ignore this email.</p>
      <p style="color:#999;font-size:12px;margin-top:24px;border-top:1px solid #eee;padding-top:12px">— Ribbon Reflector</p>
    </div>`,
  });
}


function sendPasswordResetEmail(user, token) {
  const url = `${FRONTEND_URL}/?reset=${encodeURIComponent(token)}`;
  return sendEmail({
    to: user.email,
    subject: 'Reset your password — Ribbon Reflector',
    text: `Hi ${user.handle},\n\nWe got a request to reset your Ribbon Reflector password. Click the link below to choose a new one:\n\n${url}\n\nThis link expires in 1 hour. If you didn't request this, ignore this email — your password won't change.\n\n— Ribbon Reflector`,
    html: `<div style="font-family:-apple-system,Segoe UI,sans-serif;max-width:520px;margin:0 auto;padding:24px;color:#1a1a1a">
      <h2 style="margin:0 0 14px">Reset your password</h2>
      <p>Hi ${user.handle},</p>
      <p>We got a request to reset your Ribbon Reflector password. Click the button below to choose a new one.</p>
      <p style="margin:24px 0"><a href="${url}" style="display:inline-block;background:#1a1a1a;color:#fff;padding:12px 22px;border-radius:8px;text-decoration:none;font-weight:600">Reset password</a></p>
      <p style="color:#666;font-size:13px">Or paste this link into your browser:<br><span style="color:#999">${url}</span></p>
      <p style="color:#666;font-size:13px;margin-top:20px">This link expires in 1 hour. If you didn't request this, ignore this email — your password won't change.</p>
      <p style="color:#999;font-size:12px;margin-top:24px;border-top:1px solid #eee;padding-top:12px">— Ribbon Reflector</p>
    </div>`,
  });
}


// Generic transactional template — keeps the from/branding consistent.
// Pass the subject, a 1-line headline, the body paragraphs (HTML strings),
// and an optional CTA { label, url }. Body fragments should already be HTML-safe.
function sendTransactionalEmail(user, { subject, headline, body, cta }) {
  if (!user?.email) return Promise.resolve({ skipped: 'no email' });
  const ctaHTML = cta
    ? `<p style="margin:24px 0"><a href="${cta.url}" style="display:inline-block;background:#1a1a1a;color:#fff;padding:12px 22px;border-radius:8px;text-decoration:none;font-weight:600">${cta.label}</a></p>`
    : '';
  const ctaText = cta ? `\n\n${cta.label}: ${cta.url}` : '';
  const bodyHTML = body.map(p => `<p>${p}</p>`).join('');
  const bodyText = body.map(p => p.replace(/<[^>]+>/g, '')).join('\n\n');
  return sendEmail({
    to: user.email,
    subject,
    text: `Hi ${user.handle},\n\n${headline.replace(/<[^>]+>/g, '')}\n\n${bodyText}${ctaText}\n\n— Ribbon Reflector`,
    html: `<div style="font-family:-apple-system,Segoe UI,sans-serif;max-width:520px;margin:0 auto;padding:24px;color:#1a1a1a">
      <h2 style="margin:0 0 14px">${headline}</h2>
      <p>Hi ${user.handle},</p>
      ${bodyHTML}
      ${ctaHTML}
      <p style="color:#999;font-size:12px;margin-top:24px;border-top:1px solid #eee;padding-top:12px">
        — Ribbon Reflector<br>
        <a href="${FRONTEND_URL}" style="color:#999">${FRONTEND_URL.replace(/^https?:\/\//, '')}</a>
      </p>
    </div>`,
  }).catch(e => { console.error('[tx-email] failed:', e.message); return { failed: true }; });
}

// Helper to grab user record for emailing — we often have only an ID at the notify site.
function getUserForEmail(userId) {
  return db.prepare('SELECT id, handle, email FROM users WHERE id=?').get(userId);
}


// ===== STRIPE (Phase 1) =====
const Stripe = require('stripe');
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_PUBLISHABLE_KEY = process.env.STRIPE_PUBLISHABLE_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;
if (!stripe) console.warn('[stripe] STRIPE_SECRET_KEY not set — payment endpoints will return 503.');

function stripeRequired(req, res, next) {
  if (!stripe) return res.status(503).json({ error: 'payments not configured on server' });
  next();
}

// Sellers can't accept offers until their Stripe Connect account is fully enabled.
// 'pending' means they started onboarding but haven't finished (KYC, bank, etc.).
function payoutsRequired(req, res, next) {
  if (req.user.stripe_account_status !== 'enabled') {
    return res.status(403).json({
      error: 'connect a payout method before accepting offers',
      needs_payouts_setup: true,
    });
  }
  next();
}

// Map a Stripe account record to our internal status string.
// 'enabled' = ready to receive payouts; 'pending' = onboarding incomplete; 'none' = no account.
function deriveStripeStatus(account) {
  if (!account) return 'none';
  if (account.charges_enabled && account.payouts_enabled && account.details_submitted) return 'enabled';
  return 'pending';
}

// ===== PAYMENT LIFECYCLE HELPERS (Phase 2) =====
// Returns true if the trade's payment window has expired.
function isPaymentExpired(trade) {
  if (!trade.payment_window_expires_at) return false;
  const exp = Date.parse(trade.payment_window_expires_at);
  return Number.isFinite(exp) && Date.now() > exp;
}

// Called lazily on trade fetch. If payment window has expired while trade is still
// 'pending', void the PaymentIntent and mark the trade canceled. Idempotent.
async function sweepExpiredPayment(tradeId) {
  const t = db.prepare('SELECT * FROM trades WHERE id=?').get(tradeId);
  if (!t) return;
  if (t.payment_status !== 'pending' || !isPaymentExpired(t)) return;
  console.log(`[payment-sweep] trade ${t.id} payment window expired — canceling`);
  if (stripe && t.payment_intent_id) {
    try { await stripe.paymentIntents.cancel(t.payment_intent_id); }
    catch (e) { console.error('[payment-sweep] PI cancel failed:', e.message); }
  }
  const tx = db.transaction(() => {
    db.prepare(`UPDATE trades SET payment_status='canceled', status='canceled' WHERE id=?`).run(t.id);
    // Return listing to active so seller can sell to someone else.
    db.prepare(`UPDATE listings SET status='active' WHERE id=?`).run(t.listing_id);
  });
  tx();
  notify(t.buyer_id,  '⏰', 'Your payment window expired — offer canceled.', 'myTickets', { tab:'outgoing' });
  notify(t.seller_id, '⏰', 'Buyer didn\'t complete payment in time — your listing is live again.', 'myTickets');
}

// Gate on mark-sent: seller can't mark sent until buyer has actually paid (PI captured).
function paidRequired(req, res, next) {
  // We only have trade.id at this middleware site; fetch it.
  const trade = db.prepare('SELECT payment_status FROM trades WHERE id=?').get(req.params.id);
  if (!trade) return res.status(404).json({ error: 'trade not found' });
  if (trade.payment_status !== 'paid') {
    return res.status(402).json({ error: 'waiting for buyer payment', payment_status: trade.payment_status });
  }
  next();
}

// Middleware: returns 403 until the user has verified their email.
function verifiedRequired(req, res, next) {
  if (!req.user?.email_verified) {
    return res.status(403).json({ error: 'email verification required', needs_verification: true });
  }
  next();
}


function authOptional(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const headerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const token = headerToken || req.cookies.rr_token;
  if (!token) return next();
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id, handle, email, is_member, member_until, bio, avatar_data_url, link, city, region, email_verified, email_verification_sent_at, stripe_account_id, stripe_account_status FROM users WHERE id = ?').get(payload.userId);
    if (user) req.user = user;
  } catch {}
  next();
}

// ===== NOTIFICATIONS HELPER =====
function notify(userId, icon, text, route, params) {
  db.prepare('INSERT INTO notifications (user_id, icon, text, route, params) VALUES (?, ?, ?, ?, ?)')
    .run(userId, icon, text, route || null, params ? JSON.stringify(params) : null);
}

// ===== AUTH =====
app.post('/api/auth/signup', async (req, res) => {
  const { handle, email, password, bio } = req.body;
  if (!handle || !email || !password) return res.status(400).json({ error: 'missing fields' });
  if (password.length < 8) return res.status(400).json({ error: 'password must be at least 8 chars' });
  const normHandle = handle.startsWith('@') ? handle : '@' + handle;
  let userId, verificationToken;
  try {
    const hash = bcrypt.hashSync(password, 10);
    verificationToken = crypto.randomBytes(32).toString('hex');
    const result = db.prepare(`INSERT INTO users (handle, email, password_hash, bio, email_verification_token, email_verification_sent_at, is_member, member_until)
      VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 1, date('now', '+1 year'))`)
      .run(normHandle, email, hash, bio || '', verificationToken);
    userId = result.lastInsertRowid;
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'handle or email already taken' });
    return res.status(500).json({ error: e.message });
  }
  // Fire-and-log: if the email fails we still return success; user can resend later.
  try { await sendVerificationEmail({ handle: normHandle, email }, verificationToken); }
  catch (e) { console.error('[signup] verification email failed:', e.message); }
  const token = makeToken(userId);
  res.json({ id: userId, handle: normHandle, email, is_member: 1, email_verified: 0, token });
});

// Confirm ownership of the email address via the token sent at signup.
// Public (no auth required) — the token itself is the credential.
app.post('/api/auth/verify-email/:token', (req, res) => {
  const token = req.params.token;
  const user = db.prepare('SELECT * FROM users WHERE email_verification_token=?').get(token);
  if (!user) return res.status(404).json({ error: 'invalid or expired verification link' });
  if (user.email_verified) {
    // Already verified — treat as idempotent success.
    return res.json({ ok: true, handle: user.handle, already: true });
  }
  // 24-hour window on the token.
  if (user.email_verification_sent_at) {
    const sentMs = Date.parse(user.email_verification_sent_at + 'Z');
    if (Number.isFinite(sentMs) && Date.now() - sentMs > 24 * 60 * 60 * 1000) {
      return res.status(410).json({ error: 'verification link expired — request a new one' });
    }
  }
  db.prepare('UPDATE users SET email_verified=1, email_verification_token=NULL WHERE id=?').run(user.id);
  notify(user.id, '✓', 'Email verified — you can now list tickets and make offers.', 'home');
  res.json({ ok: true, handle: user.handle });
});

// Request a fresh verification email. Auth required; 60-second cooldown per user.
app.post('/api/auth/resend-verification', authRequired, async (req, res) => {
  if (req.user.email_verified) return res.json({ ok: true, already_verified: true });
  if (req.user.email_verification_sent_at) {
    const sentMs = Date.parse(req.user.email_verification_sent_at + 'Z');
    if (Number.isFinite(sentMs) && Date.now() - sentMs < 60 * 1000) {
      return res.status(429).json({ error: 'please wait a minute before requesting another email' });
    }
  }
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('UPDATE users SET email_verification_token=?, email_verification_sent_at=CURRENT_TIMESTAMP WHERE id=?')
    .run(token, req.user.id);
  try { await sendVerificationEmail(req.user, token); }
  catch (e) { return res.status(500).json({ error: 'could not send email: ' + e.message }); }
  res.json({ ok: true });
});

// Public — frontend reads this on load to get the publishable key (no need to hardcode).
app.get('/api/stripe/config', (req, res) => {
  res.json({ publishable_key: STRIPE_PUBLISHABLE_KEY, configured: !!stripe });
});

// Create or refresh an Express onboarding link. Idempotent — reuses existing account if any.
app.post('/api/stripe/connect-onboarding', authRequired, verifiedRequired, stripeRequired, async (req, res) => {
  let acctId = req.user.stripe_account_id;
  try {
    if (!acctId) {
      const acct = await stripe.accounts.create({
        type: 'express',
        country: 'US', // CA accounts can be created the same way; we let Stripe pick up locale on the onboarding form.
        email: req.user.email,
        capabilities: { transfers: { requested: true }, card_payments: { requested: true } },
        business_type: 'individual',
        metadata: { rr_user_id: String(req.user.id), rr_handle: req.user.handle },
      });
      acctId = acct.id;
      db.prepare(`UPDATE users SET stripe_account_id=?, stripe_account_status='pending' WHERE id=?`).run(acctId, req.user.id);
    }
    const link = await stripe.accountLinks.create({
      account: acctId,
      refresh_url: `${FRONTEND_URL}/?stripe_return=1`,
      return_url: `${FRONTEND_URL}/?stripe_return=1`,
      type: 'account_onboarding',
    });
    res.json({ url: link.url, account_id: acctId });
  } catch (e) {
    console.error('[stripe] connect-onboarding failed:', e.message);
    res.status(500).json({ error: 'could not start onboarding: ' + e.message });
  }
});

// Pull live status from Stripe and sync our DB. Frontend polls this after the user returns from the onboarding flow.
app.get('/api/stripe/account-status', authRequired, stripeRequired, async (req, res) => {
  if (!req.user.stripe_account_id) return res.json({ status: 'none' });
  try {
    const acct = await stripe.accounts.retrieve(req.user.stripe_account_id);
    const status = deriveStripeStatus(acct);
    if (status !== req.user.stripe_account_status) {
      db.prepare('UPDATE users SET stripe_account_status=? WHERE id=?').run(status, req.user.id);
    }
    res.json({
      status,
      details_submitted: acct.details_submitted,
      charges_enabled: acct.charges_enabled,
      payouts_enabled: acct.payouts_enabled,
      requirements: acct.requirements?.currently_due || [],
    });
  } catch (e) {
    console.error('[stripe] account-status failed:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Login link for sellers to access their Stripe Express dashboard (view payouts, update bank, etc.)
app.post('/api/stripe/dashboard-link', authRequired, stripeRequired, async (req, res) => {
  if (!req.user.stripe_account_id) return res.status(400).json({ error: 'no stripe account' });
  try {
    const link = await stripe.accounts.createLoginLink(req.user.stripe_account_id);
    res.json({ url: link.url });
  } catch (e) {
    console.error('[stripe] dashboard-link failed:', e.message);
    res.status(500).json({ error: e.message });
  }
});


// Public — request a reset link. Always returns 200 (don't leak whether email exists).
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body || {};
  if (!email || typeof email !== 'string') return res.status(400).json({ error: 'email required' });
  const user = db.prepare('SELECT id, handle, email FROM users WHERE email=?').get(email.trim().toLowerCase());
  // Bail silently if no user — prevents email enumeration. Frontend message is generic.
  if (!user) return res.json({ ok: true });
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
  db.prepare('UPDATE users SET password_reset_token=?, password_reset_expires_at=? WHERE id=?')
    .run(token, expiresAt, user.id);
  try { await sendPasswordResetEmail(user, token); }
  catch (e) { console.error('[forgot-password] email failed:', e.message); }
  res.json({ ok: true });
});

// Public — consume the token + set a new password. Token is one-shot (cleared on success).
app.post('/api/auth/reset-password/:token', (req, res) => {
  const { password } = req.body || {};
  if (!password || password.length < 8) return res.status(400).json({ error: 'password must be at least 8 chars' });
  const user = db.prepare('SELECT * FROM users WHERE password_reset_token=?').get(req.params.token);
  if (!user) return res.status(404).json({ error: 'invalid or expired reset link' });
  if (user.password_reset_expires_at) {
    const exp = Date.parse(user.password_reset_expires_at);
    if (Number.isFinite(exp) && Date.now() > exp) {
      return res.status(410).json({ error: 'reset link expired — request a new one' });
    }
  }
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('UPDATE users SET password_hash=?, password_reset_token=NULL, password_reset_expires_at=NULL WHERE id=?')
    .run(hash, user.id);
  notify(user.id, '🔒', 'Your password was reset. If this wasn\'t you, contact support immediately.', 'home');
  // Auto-login on success — saves the user a second flow.
  const token = makeToken(user.id);
  res.json({ ok: true, handle: user.handle, email: user.email, token });
});


app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  const token = makeToken(user.id);
  res.json({ id: user.id, handle: user.handle, email: user.email, is_member: user.is_member, member_until: user.member_until, email_verified: user.email_verified, token });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('rr_token');
  res.json({ ok: true });
});

app.get('/api/me', authRequired, (req, res) => res.json(req.user));

// Update profile fields. All fields are optional; pass only the ones to change.
// Avatar is sent as a base64 data URL string; client should resize before posting.
app.patch('/api/me', authRequired, verifiedRequired, (req, res) => {
  const { bio, link, city, region, avatar_data_url } = req.body;
  if (avatar_data_url != null && typeof avatar_data_url === 'string' && avatar_data_url.length > 2_000_000) {
    return res.status(413).json({ error: 'avatar too large — please use a smaller image' });
  }
  if (link != null && typeof link === 'string' && link.length > 200) {
    return res.status(400).json({ error: 'link too long (200 char max)' });
  }
  if (bio != null && typeof bio === 'string' && bio.length > 500) {
    return res.status(400).json({ error: 'bio too long (500 char max)' });
  }
  const fields = [], values = [];
  for (const [k, v] of Object.entries({ bio, link, city, region, avatar_data_url })) {
    if (v !== undefined) { fields.push(`${k}=?`); values.push(v === '' ? null : v); }
  }
  if (!fields.length) return res.status(400).json({ error: 'no fields to update' });
  values.push(req.user.id);
  db.prepare(`UPDATE users SET ${fields.join(', ')} WHERE id=?`).run(...values);
  const updated = db.prepare('SELECT id, handle, email, is_member, member_until, bio, avatar_data_url, link, city, region FROM users WHERE id=?').get(req.user.id);
  res.json(updated);
});

// ===== MEMBERSHIP CHECKOUT =====
app.post('/api/checkout/membership', authRequired, (req, res) => {
  // Mock Stripe. Real impl: create PaymentIntent, confirm with payment_method from client.
  const charge = mockStripeCharge({ userId: req.user.id, amountCents: MEMBERSHIP_CENTS, description: 'Annual membership' });
  const until = new Date(); until.setFullYear(until.getFullYear() + 1);
  db.prepare('UPDATE users SET is_member = 1, member_until = ?, stripe_customer_id = COALESCE(stripe_customer_id, ?) WHERE id = ?')
    .run(until.toISOString().slice(0,10), 'cus_mock_' + req.user.id, req.user.id);
  db.prepare('INSERT INTO payments (user_id, kind, amount_cents, stripe_id) VALUES (?, ?, ?, ?)')
    .run(req.user.id, 'membership', MEMBERSHIP_CENTS, charge.id);
  notify(req.user.id, '✨', 'Welcome to Ribbon Reflector! Your membership is active.', 'home');
  res.json({ ok: true, charge_id: charge.id, member_until: until.toISOString().slice(0,10) });
});

// ===== LISTINGS =====
app.get('/api/listings', (req, res) => {
  const { q, city, max_price, sort, owner } = req.query;
  // When querying a specific owner, show all their listings (including pending/traded)
  // For owner queries we include active trade info so the seller can click straight through to their wallet.
  let sql = owner
    ? `SELECT l.*, u.handle AS owner_handle,
         (SELECT t.id FROM trades t WHERE t.listing_id=l.id AND t.status!='canceled' ORDER BY t.id DESC LIMIT 1) AS active_trade_id,
         (SELECT t.payment_status FROM trades t WHERE t.listing_id=l.id AND t.status!='canceled' ORDER BY t.id DESC LIMIT 1) AS active_trade_payment_status
         FROM listings l JOIN users u ON u.id = l.owner_id WHERE 1=1`
    : `SELECT l.*, u.handle AS owner_handle FROM listings l JOIN users u ON u.id = l.owner_id WHERE l.status = 'active'`;
  const params = [];
  if (q)         { sql += ' AND (l.artist LIKE ? OR l.venue LIKE ? OR l.city LIKE ?)'; const p = `%${q}%`; params.push(p,p,p); }
  if (city)      { sql += ' AND l.city = ?'; params.push(city); }
  if (max_price) { sql += ' AND l.face_value <= ?'; params.push(Number(max_price)); }
  if (owner)     { sql += ' AND u.handle = ?'; params.push(owner); }
  sql += ({
    'price-low':  ' ORDER BY l.face_value ASC',
    'price-high': ' ORDER BY l.face_value DESC',
    'artist':     ' ORDER BY l.artist ASC',
  }[sort] || ' ORDER BY l.created_at DESC');
  res.json(db.prepare(sql).all(...params));
});

app.get('/api/listings/:id', (req, res) => {
  const row = db.prepare(`SELECT l.*, u.handle AS owner_handle FROM listings l JOIN users u ON u.id = l.owner_id WHERE l.id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json(row);
});

app.post('/api/listings', authRequired, memberRequired, verifiedRequired, (req, res) => {
  const { artist, venue, city, event_date, seat, qty, face_value, source, notes, receipt_filename } = req.body;
  if (!artist || !venue || !face_value) return res.status(400).json({ error: 'artist, venue, face_value required' });
  if (!receipt_filename) return res.status(400).json({ error: 'face-value receipt required' });
  const result = db.prepare(`INSERT INTO listings
    (owner_id, artist, venue, city, event_date, seat, qty, face_value, source, notes, receipt_filename, status)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,'pending')`)
    .run(req.user.id, artist, venue, city||null, event_date||null, seat||null, qty||1, face_value, source||null, notes||null, receipt_filename);
  notify(req.user.id, '📝', `Listing for <strong>${artist}</strong> submitted for review.`, 'myTickets');
  // In production, a moderator or automated check verifies face value before setting to 'active'.
  // For the scaffold we auto-approve after a short delay:
  setTimeout(() => {
    db.prepare(`UPDATE listings SET status='active' WHERE id=?`).run(result.lastInsertRowid);
    notify(req.user.id, '✓', `Your <strong>${artist}</strong> listing is now live.`, 'myTickets');
  }, 2000);
  res.json({ id: result.lastInsertRowid });
});

// Grouped by event (artist+venue+date)
app.get('/api/events/:key', (req, res) => {
  const [artist, venue, event_date] = req.params.key.split('|');
  const listings = db.prepare(`SELECT l.*, u.handle AS owner_handle FROM listings l JOIN users u ON u.id=l.owner_id
    WHERE l.artist=? AND l.venue=? AND l.event_date=? AND l.status='active'`).all(artist, venue, event_date);
  res.json({ artist, venue, event_date, listings });
});

// ===== USER PROFILES =====
app.get('/api/users/:handle', authOptional, (req, res) => {
  const handle = req.params.handle.startsWith('@') ? req.params.handle : '@' + req.params.handle;
  const user = db.prepare('SELECT id, handle, bio, avatar_data_url, link, city, region, created_at FROM users WHERE handle = ?').get(handle);
  if (!user) return res.status(404).json({ error: 'not found' });
  const listings = db.prepare(`SELECT * FROM listings WHERE owner_id=? AND status='active'`).all(user.id);
  const reviews = db.prepare(`SELECT r.*, u.handle AS author_handle FROM reviews r JOIN users u ON u.id=r.author_id WHERE r.subject_id=? ORDER BY r.created_at DESC`).all(user.id);
  const avgRow = db.prepare('SELECT AVG(stars) AS avg, COUNT(*) AS n FROM reviews WHERE subject_id=?').get(user.id);
  const friendsRow = db.prepare(`SELECT COUNT(*) AS n FROM friendships WHERE status='accepted' AND (requester_id=? OR recipient_id=?)`).get(user.id, user.id);
  let friendship_status = 'none';
  if (req.user) {
    if (req.user.id === user.id) {
      friendship_status = 'self';
    } else {
      const f = db.prepare(`SELECT * FROM friendships WHERE
        (requester_id=? AND recipient_id=?) OR (requester_id=? AND recipient_id=?)`)
        .get(req.user.id, user.id, user.id, req.user.id);
      if (f) {
        if (f.status === 'accepted') friendship_status = 'friends';
        else if (f.requester_id === req.user.id) friendship_status = 'pending_outgoing';
        else friendship_status = 'pending_incoming';
      }
    }
  }
  res.json({ user, listings, reviews,
    trust_score: avgRow.n ? Math.round((avgRow.avg/5)*100) : 0,
    reviews_count: avgRow.n,
    friends_count: friendsRow.n,
    friendship_status,
  });
});

// ===== OFFERS (cash-only, one-directional) =====
// Buyer makes a cash offer from $0.01 up to (never above) the target listing's face_value.
// amount_cents is authoritative and enforced server-side; frontend cap is a courtesy only.
app.post('/api/offers', authRequired, memberRequired, verifiedRequired, (req, res) => {
  const { target_listing_id, amount_cents, note } = req.body;

  // Coerce and validate amount_cents — must be a positive integer.
  const amt = Number.parseInt(amount_cents, 10);
  if (!Number.isFinite(amt) || amt <= 0) {
    return res.status(400).json({ error: 'amount_cents must be a positive integer' });
  }

  const target = db.prepare('SELECT * FROM listings WHERE id=?').get(target_listing_id);
  if (!target) return res.status(404).json({ error: 'listing not found' });
  if (target.owner_id === req.user.id) return res.status(400).json({ error: 'cannot offer on your own listing' });
  if (target.status !== 'active') return res.status(400).json({ error: 'listing is not available' });

  // Hard cap: offer cannot exceed face value. Face value is stored as REAL dollars;
  // convert to cents with rounding to avoid float drift (e.g. 49.99 → 4999).
  const faceCents = Math.round(Number(target.face_value) * 100);
  if (amt > faceCents) {
    return res.status(400).json({ error: `offer cannot exceed face value ($${(faceCents/100).toFixed(2)})` });
  }

  const result = db.prepare(
    `INSERT INTO offers (from_user_id, to_user_id, target_listing_id, amount_cents, note) VALUES (?,?,?,?,?)`
  ).run(req.user.id, target.owner_id, target_listing_id, amt, note || '');

  notify(
    target.owner_id,
    '🎟️',
    `<strong>${req.user.handle}</strong> offered $${(amt/100).toFixed(2)} for your ${target.artist} ticket.`,
    'myTickets',
    { tab: 'incoming' }
  );
  res.json({ id: result.lastInsertRowid });
});

app.get('/api/offers/incoming', authRequired, (req, res) => {
  // Cash-mode incoming offers: only pending offers on listings owned by the caller.
  // Returns everything the seller needs to display the offer and decide accept/decline.
  // No join to an "offered listing" — there isn't one under cash-mode.
  res.json(db.prepare(`SELECT
      o.id, o.amount_cents, o.note, o.status, o.created_at,
      o.from_user_id, u.handle AS from_handle,
      o.target_listing_id,
      tl.artist AS target_artist, tl.venue AS target_venue, tl.city AS target_city,
      tl.event_date AS target_date, tl.seat AS target_seat, tl.face_value AS target_face_value
    FROM offers o
    JOIN users u ON u.id=o.from_user_id
    JOIN listings tl ON tl.id=o.target_listing_id
    WHERE o.to_user_id=? AND o.status='pending'
    ORDER BY o.created_at DESC`).all(req.user.id));
});

app.get('/api/offers/outgoing', authRequired, (req, res) => {
  // Left-join trades so that accepted offers carry the trade_id + payment_status the buyer
  // needs to jump to the payment flow.
  res.json(db.prepare(`SELECT o.*, u.handle AS to_handle,
    tl.artist AS target_artist, tl.venue AS target_venue,
    t.id AS trade_id, t.payment_status AS trade_payment_status
    FROM offers o
    JOIN users u ON u.id=o.to_user_id
    JOIN listings tl ON tl.id=o.target_listing_id
    LEFT JOIN trades t ON t.offer_id=o.id
    WHERE o.from_user_id=? ORDER BY o.created_at DESC`).all(req.user.id));
});

// Accept an offer (cash-mode): charge buyer for amount_cents, create trade, mark listing traded, auto-decline siblings.
// Seller is the acceptor (offer.to_user_id); buyer is offer.from_user_id.
app.post('/api/offers/:id/accept', authRequired, verifiedRequired, payoutsRequired, async (req, res) => {
  const offer = db.prepare('SELECT * FROM offers WHERE id=?').get(req.params.id);
  if (!offer) return res.status(404).json({ error: 'not found' });
  if (offer.to_user_id !== req.user.id) return res.status(403).json({ error: 'not your offer to accept' });
  if (offer.status !== 'pending') return res.status(400).json({ error: 'offer already ' + offer.status });

  const listing = db.prepare('SELECT * FROM listings WHERE id=?').get(offer.target_listing_id);
  if (!listing) return res.status(404).json({ error: 'listing not found' });
  if (listing.status !== 'active') return res.status(400).json({ error: 'listing is no longer available' });

  const buyerId = offer.from_user_id;
  const sellerId = offer.to_user_id;
  const amountCents = offer.amount_cents;

  // Charge buyer only. Seller is not charged under cash-mode.
  const charge = mockStripeCharge({ userId: buyerId, amountCents, description: `Escrow hold — ${listing.artist}` });

  const tx = db.transaction(() => {
    db.prepare(`UPDATE offers SET status='accepted' WHERE id=?`).run(offer.id);

    // Phase 2: no payment row here yet — we create a PaymentIntent below, after the transaction.
    // Trade starts in payment_status='pending'; listing is 'traded' but will flip back to 'active'
    // if the buyer doesn't pay within the 15-minute window (see sweepExpiredPayment).
    const tradeResult = db.prepare(`INSERT INTO trades
      (offer_id, buyer_id, seller_id, listing_id, amount_cents, escrow_charge_id, payment_status)
      VALUES (?,?,?,?,?,?,'pending')`)
      .run(offer.id, buyerId, sellerId, listing.id, amountCents, '');

    db.prepare(`UPDATE listings SET status='traded' WHERE id=?`).run(listing.id);

    // Auto-decline all other pending offers on this listing — one winner per listing.
    const siblings = db.prepare(`SELECT id, from_user_id FROM offers WHERE target_listing_id=? AND status='pending' AND id != ?`)
      .all(listing.id, offer.id);
    if (siblings.length) {
      db.prepare(`UPDATE offers SET status='declined' WHERE target_listing_id=? AND status='pending' AND id != ?`)
        .run(listing.id, offer.id);
    }

    return { tradeId: tradeResult.lastInsertRowid, siblings };
  });
  const { tradeId, siblings } = tx();

  const buyerHandle = db.prepare('SELECT handle FROM users WHERE id=?').get(buyerId).handle;
  const amountDisplay = `$${(amountCents/100).toFixed(2)}`;

  // Phase 2: create a real PaymentIntent — authorizes now, captures automatically on success.
  // TODO Phase 3: switch capture_method to 'manual' once transfer-on-complete is wired.
  let pi = null;
  try {
    pi = await stripe.paymentIntents.create({
      amount: amountCents,
      currency: 'usd',
      capture_method: 'automatic',
      metadata: {
        rr_trade_id: String(tradeId),
        rr_buyer_id: String(buyerId),
        rr_seller_id: String(sellerId),
        rr_listing_id: String(listing.id),
      },
      automatic_payment_methods: { enabled: true },
    });
  } catch (e) {
    console.error('[accept] PaymentIntent create failed:', e.message);
    db.prepare(`UPDATE trades SET payment_status='failed', status='canceled' WHERE id=?`).run(tradeId);
    db.prepare(`UPDATE listings SET status='active' WHERE id=?`).run(listing.id);
    return res.status(500).json({ error: 'could not create payment: ' + e.message });
  }

  const paymentWindowExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24-hour window during beta
  db.prepare(`UPDATE trades SET payment_intent_id=?, payment_client_secret=?, payment_window_expires_at=? WHERE id=?`)
    .run(pi.id, pi.client_secret, paymentWindowExpiresAt, tradeId);
  notify(buyerId,  '🎉', `<strong>${req.user.handle}</strong> accepted your ${amountDisplay} offer for ${listing.artist}!`, 'wallet');
  notify(sellerId, '🎉', `You accepted <strong>@${buyerHandle}</strong>'s ${amountDisplay} offer. Send the ticket next.`, 'wallet');
  // Transactional emails (best-effort — never block the response).
  const buyerUser  = getUserForEmail(buyerId);
  const sellerUser = getUserForEmail(sellerId);
  sendTransactionalEmail(buyerUser, {
    subject: `Your offer was accepted — ${listing.artist}`,
    headline: 'Your offer was accepted!',
    body: [
      `<strong>@${req.user.handle}</strong> accepted your <strong>${amountDisplay}</strong> offer for <strong>${listing.artist}</strong> at ${listing.venue}${listing.event_date ? ' on ' + listing.event_date : ''}.`,
      `Your card was charged and the funds are held in escrow. The seller will transfer the ticket next; you\'ll get another email when they mark it sent.`,
    ],
    cta: { label: 'View trade', url: `${FRONTEND_URL}` },
  });
  sendTransactionalEmail(sellerUser, {
    subject: `You accepted an offer — send the ticket next`,
    headline: 'Trade in motion',
    body: [
      `You accepted <strong>@${buyerHandle}</strong>\'s <strong>${amountDisplay}</strong> offer for <strong>${listing.artist}</strong>.`,
      `Funds are held in escrow. Transfer the ticket through your venue/ticketing app, then mark it as sent in Ribbon Reflector. Once the buyer confirms receipt, escrow releases to you.`,
    ],
    cta: { label: 'Open trade', url: `${FRONTEND_URL}` },
  });
  for (const sib of siblings) {
    notify(sib.from_user_id, '📪', `Your offer on ${listing.artist} was auto-declined because another offer was accepted.`, 'myTickets', { tab: 'outgoing' });
  }

  res.json({
    trade_id: tradeId,
    payment_client_secret: pi.client_secret,
    payment_intent_id: pi.id,
    amount_cents: amountCents,
    payment_window_expires_at: paymentWindowExpiresAt,
  });
});

// ===== PAYMENT (Phase 2) =====
// Buyer fetches the PaymentIntent client_secret to render Stripe Elements.
// Also returns the current payment window so the frontend can show a countdown.
app.get('/api/trades/:id/payment', authRequired, stripeRequired, async (req, res) => {
  await sweepExpiredPayment(req.params.id);
  const trade = db.prepare('SELECT * FROM trades WHERE id=?').get(req.params.id);
  if (!trade) return res.status(404).json({ error: 'not found' });
  if (trade.buyer_id !== req.user.id) return res.status(403).json({ error: 'only the buyer can pay' });
  if (!trade.payment_intent_id) return res.status(400).json({ error: 'no payment attached' });
  res.json({
    payment_status: trade.payment_status,
    client_secret: trade.payment_client_secret,
    amount_cents: trade.amount_cents,
    window_expires_at: trade.payment_window_expires_at,
    expired: isPaymentExpired(trade),
  });
});

// Buyer-initiated cancel (e.g. closed checkout before paying). Voids the PI, returns listing to active.
app.post('/api/trades/:id/cancel-payment', authRequired, stripeRequired, async (req, res) => {
  const trade = db.prepare('SELECT * FROM trades WHERE id=?').get(req.params.id);
  if (!trade) return res.status(404).json({ error: 'not found' });
  if (trade.buyer_id !== req.user.id) return res.status(403).json({ error: 'only the buyer can cancel' });
  if (trade.payment_status !== 'pending') return res.status(400).json({ error: 'cannot cancel once paid' });
  if (trade.payment_intent_id) {
    try { await stripe.paymentIntents.cancel(trade.payment_intent_id); }
    catch (e) { console.error('[cancel-payment] PI cancel failed:', e.message); }
  }
  const tx = db.transaction(() => {
    db.prepare(`UPDATE trades SET payment_status='canceled', status='canceled' WHERE id=?`).run(trade.id);
    db.prepare(`UPDATE listings SET status='active' WHERE id=?`).run(trade.listing_id);
  });
  tx();
  notify(trade.seller_id, '↩️', 'Buyer canceled the payment — your listing is live again.', 'myTickets');
  res.json({ ok: true });
});

// Stripe.js confirms the payment directly with Stripe on the frontend; this endpoint
// is called after that succeeds so the backend syncs payment_status to 'paid' and notifies the seller.
// We double-check by fetching the PI from Stripe to confirm it actually succeeded.
app.post('/api/trades/:id/confirm-payment', authRequired, stripeRequired, async (req, res) => {
  const trade = db.prepare('SELECT * FROM trades WHERE id=?').get(req.params.id);
  if (!trade) return res.status(404).json({ error: 'not found' });
  if (trade.buyer_id !== req.user.id) return res.status(403).json({ error: 'only the buyer can confirm' });
  if (trade.payment_status === 'paid') return res.json({ ok: true, already_paid: true });

  let pi;
  try { pi = await stripe.paymentIntents.retrieve(trade.payment_intent_id); }
  catch (e) { return res.status(500).json({ error: 'could not verify payment: ' + e.message }); }

  if (pi.status !== 'succeeded') {
    return res.status(400).json({ error: 'payment not yet succeeded', stripe_status: pi.status });
  }
  db.prepare(`UPDATE trades SET payment_status='paid' WHERE id=?`).run(trade.id);
  db.prepare(`INSERT INTO payments (user_id, kind, amount_cents, stripe_id, trade_id) VALUES (?, 'escrow_hold', ?, ?, ?)`)
    .run(trade.buyer_id, trade.amount_cents, pi.id, trade.id);
  const sellerForEmail = getUserForEmail(trade.seller_id);
  notify(trade.seller_id, '💰', 'Buyer paid — you can mark the ticket as sent now.', 'wallet');
  sendTransactionalEmail(sellerForEmail, {
    subject: 'Buyer paid — send the ticket',
    headline: 'Payment received',
    body: [
      `The buyer has paid for trade #${trade.id}. Funds are held in escrow.`,
      `Transfer the ticket through your venue app, then mark it as sent in Ribbon Reflector.`,
    ],
    cta: { label: 'Open trade', url: `${FRONTEND_URL}` },
  });
  res.json({ ok: true });
});

app.post('/api/offers/:id/decline', authRequired, (req, res) => {
  const offer = db.prepare('SELECT * FROM offers WHERE id=?').get(req.params.id);
  if (!offer || offer.to_user_id !== req.user.id) return res.status(404).json({ error: 'not found' });
  db.prepare(`UPDATE offers SET status='declined' WHERE id=?`).run(offer.id);
  notify(offer.from_user_id, '📪', `Your offer was declined.`, 'myTickets', { tab: 'outgoing' });
  res.json({ ok: true });
});

// ===== TRADES =====
// Cash-mode trade fetch: single listing, buyer + seller. Only the two parties can read.
app.get('/api/trades/:id', authRequired, async (req, res) => {
  await sweepExpiredPayment(req.params.id);
  const trade = db.prepare(`SELECT t.*,
    l.artist AS listing_artist, l.venue AS listing_venue, l.city AS listing_city,
    l.event_date AS listing_date, l.seat AS listing_seat, l.face_value AS listing_face_value,
    bu.handle AS buyer_handle, su.handle AS seller_handle
    FROM trades t
    JOIN listings l ON l.id=t.listing_id
    JOIN users bu ON bu.id=t.buyer_id
    JOIN users su ON su.id=t.seller_id
    WHERE t.id=?`).get(req.params.id);
  if (!trade || (trade.buyer_id !== req.user.id && trade.seller_id !== req.user.id)) {
    return res.status(404).json({ error: 'not found' });
  }
  // Annotate which side the caller is — saves the frontend from doing this comparison everywhere.
  trade.viewer_role = trade.buyer_id === req.user.id ? 'buyer' : 'seller';
  res.json(trade);
});

// Cash-mode one-directional handoff:
//   seller calls mark-sent → sets seller_sent=1
//   buyer calls mark-received → sets buyer_received=1
// When both are true, trade completes and escrow releases to seller (single payment row).
app.post('/api/trades/:id/mark-sent', authRequired, paidRequired, async (req, res) => {
  const trade = db.prepare('SELECT * FROM trades WHERE id=?').get(req.params.id);
  if (!trade) return res.status(404).json({ error: 'not found' });
  if (trade.status !== 'active') return res.status(400).json({ error: 'trade is ' + trade.status });
  if (trade.seller_id !== req.user.id) return res.status(403).json({ error: 'only the seller can mark sent' });
  if (trade.seller_sent) return res.status(400).json({ error: 'already marked sent' });

  db.prepare(`UPDATE trades SET seller_sent=1 WHERE id=?`).run(trade.id);
  await maybeCompleteTrade(trade.id);
  const after = db.prepare('SELECT * FROM trades WHERE id=?').get(trade.id);
  if (after.status === 'active') {
    notify(trade.buyer_id, '✈️', 'Seller marked the ticket as sent. Confirm when you receive it.', 'wallet');
    const buyerForEmail = getUserForEmail(trade.buyer_id);
    sendTransactionalEmail(buyerForEmail, {
      subject: 'Your ticket is on the way',
      headline: 'Seller marked the ticket as sent',
      body: [
        `The seller has transferred the ticket. Check your venue/ticketing app for the incoming transfer.`,
        `Once you\'ve received it, head back to Ribbon Reflector and confirm receipt — that\'s what releases the funds from escrow to the seller.`,
      ],
      cta: { label: 'Confirm receipt', url: `${FRONTEND_URL}` },
    });
  }
  res.json(after);
});

app.post('/api/trades/:id/mark-received', authRequired, async (req, res) => {
  const trade = db.prepare('SELECT * FROM trades WHERE id=?').get(req.params.id);
  if (!trade) return res.status(404).json({ error: 'not found' });
  if (trade.status !== 'active') return res.status(400).json({ error: 'trade is ' + trade.status });
  if (trade.buyer_id !== req.user.id) return res.status(403).json({ error: 'only the buyer can mark received' });
  if (trade.buyer_received) return res.status(400).json({ error: 'already marked received' });
  if (!trade.seller_sent) return res.status(400).json({ error: 'seller has not marked the ticket sent yet' });

  db.prepare(`UPDATE trades SET buyer_received=1 WHERE id=?`).run(trade.id);
  await maybeCompleteTrade(trade.id);
  const after = db.prepare('SELECT * FROM trades WHERE id=?').get(trade.id);
  res.json(after);
});

// Finalize trade + release escrow to seller if both sides are marked.
// Idempotent: safe to call repeatedly; only acts once when state transitions.
// Phase 3: creates a real Stripe Transfer from platform → seller's connected account.
async function maybeCompleteTrade(tradeId) {
  const t = db.prepare('SELECT * FROM trades WHERE id=?').get(tradeId);
  if (!t || t.status !== 'active') return;
  if (!t.seller_sent || !t.buyer_received) return;

  // Look up seller's Stripe account. If missing, still complete the trade but log the error
  // — admin will need to handle the payout manually.
  const seller = db.prepare('SELECT stripe_account_id FROM users WHERE id=?').get(t.seller_id);
  let transferId = null;

  if (stripe && seller?.stripe_account_id && t.payment_intent_id) {
    try {
      // Retrieve the charge ID from the PaymentIntent so we can tie the transfer to it.
      // This avoids the 'insufficient available funds' error by drawing from the specific charge.
      const pi = await stripe.paymentIntents.retrieve(t.payment_intent_id);
      const chargeId = pi.latest_charge;
      const transfer = await stripe.transfers.create({
        amount: t.amount_cents,
        currency: 'usd',
        destination: seller.stripe_account_id,
        source_transaction: chargeId,
        transfer_group: `trade_${t.id}`,
        metadata: {
          rr_trade_id: String(t.id),
          rr_seller_id: String(t.seller_id),
          rr_buyer_id: String(t.buyer_id),
        },
      });
      transferId = transfer.id;
      console.log(`[transfer] trade ${t.id}: ${transfer.id} → ${seller.stripe_account_id} ($${(t.amount_cents/100).toFixed(2)})`);
    } catch (e) {
      // Log but don't block trade completion — admin resolves manually.
      console.error(`[transfer] trade ${t.id} FAILED:`, e.message);
    }
  } else {
    console.warn(`[transfer] trade ${t.id}: skipped — stripe=${!!stripe}, seller_acct=${seller?.stripe_account_id}, pi=${t.payment_intent_id}`);
  }

  const tx = db.transaction(() => {
    db.prepare(`UPDATE trades SET status='complete', completed_at=CURRENT_TIMESTAMP, transfer_id=? WHERE id=?`).run(transferId, t.id);
    const hold = db.prepare(`SELECT * FROM payments WHERE trade_id=? AND kind='escrow_hold'`).get(t.id);
    const releaseStripeId = transferId || (hold ? 'rel_' + hold.stripe_id : 'rel_unknown_' + t.id);
    db.prepare(`INSERT INTO payments (user_id, kind, amount_cents, stripe_id, trade_id) VALUES (?, 'escrow_release', ?, ?, ?)`)
      .run(t.seller_id, t.amount_cents, releaseStripeId, t.id);
  });
  tx();

  notify(t.buyer_id,  '✓', 'Trade complete — enjoy the show! Leave a review when you can.', 'reviews');
  notify(t.seller_id, '✓', 'Trade complete — escrow released to you. Leave a review for the buyer.', 'reviews');
  const buyerDone  = getUserForEmail(t.buyer_id);
  const sellerDone = getUserForEmail(t.seller_id);
  sendTransactionalEmail(buyerDone, {
    subject: 'Trade complete — enjoy the show 🎟️',
    headline: 'You\'re all set',
    body: [
      `You confirmed receipt and escrow has been released to the seller. The trade is complete.`,
      `If everything went smoothly, leaving a quick review helps the next fan trust this seller.`,
    ],
    cta: { label: 'Leave a review', url: `${FRONTEND_URL}` },
  });
  sendTransactionalEmail(sellerDone, {
    subject: 'Trade complete — escrow released',
    headline: 'Funds released to you',
    body: [
      `The buyer confirmed receipt of the ticket and escrow has been released. The trade is complete.`,
      `Help the buyer build their reputation by leaving a quick review.`,
    ],
    cta: { label: 'Leave a review', url: `${FRONTEND_URL}` },
  });
}

// ===== MESSAGES =====
app.get('/api/trades/:id/messages', authRequired, (req, res) => {
  const trade = db.prepare('SELECT * FROM trades WHERE id=?').get(req.params.id);
  if (!trade || (trade.buyer_id !== req.user.id && trade.seller_id !== req.user.id)) return res.status(404).json({ error: 'not found' });
  res.json(db.prepare(`SELECT m.*, u.handle AS sender_handle FROM messages m JOIN users u ON u.id=m.sender_id WHERE trade_id=? ORDER BY created_at ASC`).all(trade.id));
});

app.post('/api/trades/:id/messages', authRequired, (req, res) => {
  const trade = db.prepare('SELECT * FROM trades WHERE id=?').get(req.params.id);
  if (!trade || (trade.buyer_id !== req.user.id && trade.seller_id !== req.user.id)) return res.status(404).json({ error: 'not found' });
  const { body } = req.body;
  if (!body?.trim()) return res.status(400).json({ error: 'empty message' });
  const result = db.prepare('INSERT INTO messages (trade_id, sender_id, body) VALUES (?,?,?)').run(trade.id, req.user.id, body.trim());
  const otherUser = trade.buyer_id === req.user.id ? trade.seller_id : trade.buyer_id;
  notify(otherUser, '💬', `New message from <strong>${req.user.handle}</strong>.`, 'wallet');
  res.json({ id: result.lastInsertRowid });
});

// ===== DISPUTES =====
app.post('/api/trades/:id/dispute', authRequired, (req, res) => {
  const trade = db.prepare('SELECT * FROM trades WHERE id=?').get(req.params.id);
  if (!trade || (trade.buyer_id !== req.user.id && trade.seller_id !== req.user.id)) return res.status(404).json({ error: 'not found' });
  if (trade.status !== 'active') return res.status(400).json({ error: 'trade is ' + trade.status });
  const { reason, details, evidence_filename } = req.body;
  if (!reason || !details) return res.status(400).json({ error: 'reason and details required' });
  db.prepare('INSERT INTO disputes (trade_id, filed_by_id, reason, details, evidence_filename) VALUES (?,?,?,?,?)')
    .run(trade.id, req.user.id, reason, details, evidence_filename || null);
  db.prepare(`UPDATE trades SET status='disputed' WHERE id=?`).run(trade.id);
  notify(trade.buyer_id,  '⚠️', `Dispute opened on trade #${trade.id}. Support will reach out within 24h.`, 'wallet');
  notify(trade.seller_id, '⚠️', `Dispute opened on trade #${trade.id}. Support will reach out within 24h.`, 'wallet');
  const buyerDispute  = getUserForEmail(trade.buyer_id);
  const sellerDispute = getUserForEmail(trade.seller_id);
  for (const u of [buyerDispute, sellerDispute]) {
    sendTransactionalEmail(u, {
      subject: `Dispute opened — trade #${trade.id}`,
      headline: 'A dispute was filed on your trade',
      body: [
        `A dispute was filed on trade #${trade.id}. Funds are held in escrow until the case is resolved.`,
        `Our support team will email both parties within 24 hours. In the meantime, please don\'t take any further action on this trade.`,
      ],
      cta: { label: 'View trade', url: `${FRONTEND_URL}` },
    });
  }
  res.json({ ok: true });
});

// ===== REVIEWS =====
app.post('/api/reviews', authRequired, verifiedRequired, (req, res) => {
  const { trade_id, stars, body } = req.body;
  if (!trade_id || !stars) return res.status(400).json({ error: 'trade_id and stars required' });
  const starsInt = Number.parseInt(stars, 10);
  if (!Number.isFinite(starsInt) || starsInt < 1 || starsInt > 5) return res.status(400).json({ error: 'stars must be 1-5' });
  const trade = db.prepare('SELECT * FROM trades WHERE id=?').get(trade_id);
  if (!trade) return res.status(404).json({ error: 'trade not found' });
  if (trade.buyer_id !== req.user.id && trade.seller_id !== req.user.id) return res.status(403).json({ error: 'not your trade' });
  if (trade.status !== 'complete') return res.status(400).json({ error: 'can only review completed trades' });
  const existing = db.prepare('SELECT id FROM reviews WHERE trade_id=? AND author_id=?').get(trade_id, req.user.id);
  if (existing) return res.status(409).json({ error: 'you have already reviewed this trade' });
  const subject = trade.buyer_id === req.user.id ? trade.seller_id : trade.buyer_id;
  const result = db.prepare('INSERT INTO reviews (trade_id, author_id, subject_id, stars, body) VALUES (?,?,?,?,?)')
    .run(trade_id, req.user.id, subject, starsInt, body || '');
  const subjectUser = getUserForEmail(subject);
  notify(subject, '⭐', `<strong>${req.user.handle}</strong> left you a ${starsInt}-star review.`, 'profile', { handle: subjectUser.handle });
  sendTransactionalEmail(subjectUser, {
    subject: `${req.user.handle} left you a ${starsInt}-star review`,
    headline: `New review from @${req.user.handle.replace('@','')}`,
    body: [
      `<strong>@${req.user.handle.replace('@','')}</strong> left you a <strong>${starsInt}-star</strong> review.`,
      body ? `&ldquo;${body.replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'})[c])}&rdquo;` : `(No comment.)`,
    ],
    cta: { label: 'View your profile', url: `${FRONTEND_URL}` },
  });
  res.json({ id: result.lastInsertRowid });
});

// ===== FRIENDS =====
app.get('/api/friends', authRequired, (req, res) => {
  const me = req.user.id;
  const rows = db.prepare(`SELECT f.*, ru.handle AS requester_handle, cu.handle AS recipient_handle
    FROM friendships f
    JOIN users ru ON ru.id = f.requester_id
    JOIN users cu ON cu.id = f.recipient_id
    WHERE f.requester_id=? OR f.recipient_id=?
    ORDER BY f.created_at DESC`).all(me, me);
  const friends = [], incoming = [], outgoing = [];
  for (const r of rows) {
    const otherHandle = r.requester_id === me ? r.recipient_handle : r.requester_handle;
    if (r.status === 'accepted') friends.push({ id: r.id, handle: otherHandle, since: r.accepted_at });
    else if (r.requester_id === me) outgoing.push({ id: r.id, handle: otherHandle, sent_at: r.created_at });
    else incoming.push({ id: r.id, handle: otherHandle, sent_at: r.created_at });
  }
  res.json({ friends, incoming, outgoing });
});

app.post('/api/friends/:handle', authRequired, verifiedRequired, (req, res) => {
  const handle = req.params.handle.startsWith('@') ? req.params.handle : '@' + req.params.handle;
  const target = db.prepare('SELECT id, handle FROM users WHERE handle=?').get(handle);
  if (!target) return res.status(404).json({ error: 'user not found' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'cannot friend yourself' });
  const existing = db.prepare(`SELECT * FROM friendships WHERE
    (requester_id=? AND recipient_id=?) OR (requester_id=? AND recipient_id=?)`)
    .get(req.user.id, target.id, target.id, req.user.id);
  if (existing) {
    if (existing.status === 'accepted') return res.json({ status: 'friends' });
    if (existing.requester_id === req.user.id) return res.json({ status: 'pending_outgoing' });
    db.prepare(`UPDATE friendships SET status='accepted', accepted_at=CURRENT_TIMESTAMP WHERE id=?`).run(existing.id);
    notify(target.id, '🤝', `<strong>${req.user.handle}</strong> accepted your friend request.`, 'profile', { handle: req.user.handle });
    return res.json({ status: 'friends' });
  }
  db.prepare('INSERT INTO friendships (requester_id, recipient_id) VALUES (?,?)').run(req.user.id, target.id);
  notify(target.id, '🤝', `<strong>${req.user.handle}</strong> sent you a friend request.`, 'profile', { handle: req.user.handle });
  res.json({ status: 'pending_outgoing' });
});

app.post('/api/friends/:handle/accept', authRequired, (req, res) => {
  const handle = req.params.handle.startsWith('@') ? req.params.handle : '@' + req.params.handle;
  const requester = db.prepare('SELECT id, handle FROM users WHERE handle=?').get(handle);
  if (!requester) return res.status(404).json({ error: 'user not found' });
  const f = db.prepare(`SELECT * FROM friendships WHERE requester_id=? AND recipient_id=? AND status='pending'`)
    .get(requester.id, req.user.id);
  if (!f) return res.status(404).json({ error: 'no pending request from this user' });
  db.prepare(`UPDATE friendships SET status='accepted', accepted_at=CURRENT_TIMESTAMP WHERE id=?`).run(f.id);
  notify(requester.id, '🤝', `<strong>${req.user.handle}</strong> accepted your friend request.`, 'profile', { handle: req.user.handle });
  res.json({ status: 'friends' });
});

app.delete('/api/friends/:handle', authRequired, (req, res) => {
  const handle = req.params.handle.startsWith('@') ? req.params.handle : '@' + req.params.handle;
  const other = db.prepare('SELECT id FROM users WHERE handle=?').get(handle);
  if (!other) return res.status(404).json({ error: 'user not found' });
  const result = db.prepare(`DELETE FROM friendships WHERE
    (requester_id=? AND recipient_id=?) OR (requester_id=? AND recipient_id=?)`)
    .run(req.user.id, other.id, other.id, req.user.id);
  res.json({ status: 'none', removed: result.changes });
});

// ===== NOTIFICATIONS =====
app.get('/api/notifications', authRequired, (req, res) => {
  const rows = db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50').all(req.user.id);
  res.json(rows.map(r => ({ ...r, params: r.params ? JSON.parse(r.params) : null, is_read: !!r.is_read })));
});
app.post('/api/notifications/read-all', authRequired, (req, res) => {
  db.prepare('UPDATE notifications SET is_read=1 WHERE user_id=?').run(req.user.id);
  res.json({ ok: true });
});
app.post('/api/notifications/:id/read', authRequired, (req, res) => {
  db.prepare('UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ===== DEV ONLY — remove before production =====
// Delete a user by email so you can retry signup after a failed attempt.
// Protected by a secret header so random internet can't call it.
app.post('/api/dev/delete-user', (req, res) => {
  if (req.headers['x-dev-secret'] !== (process.env.JWT_SECRET || 'dev-secret-change-in-production')) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'email required' });
  const result = db.prepare('DELETE FROM users WHERE email = ?').run(email);
  res.json({ deleted: result.changes });
});

// ===== ACCOUNT DELETION =====
// Cascading delete: removes user + their listings, offers, trades (orphaned),
// reviews, notifications, friendships. Respects foreign key cascades if schema has them,
// otherwise does explicit cleanup.
app.delete('/api/me', authRequired, async (req, res) => {
  const userId = req.user.id;
  const handle = req.user.handle;
  try {
    const tx = db.transaction(() => {
      // Cancel any active trades where this user is a party (buyer or seller).
      const activeTrades = db.prepare(`SELECT * FROM trades WHERE (buyer_id=? OR seller_id=?) AND status='active'`).all(userId, userId);
      for (const t of activeTrades) {
        db.prepare(`UPDATE trades SET status='canceled' WHERE id=?`).run(t.id);
        db.prepare(`UPDATE listings SET status='active' WHERE id=?`).run(t.listing_id);
        // Void any pending Stripe PaymentIntents.
        if (stripe && t.payment_intent_id && t.payment_status === 'pending') {
          stripe.paymentIntents.cancel(t.payment_intent_id).catch(e =>
            console.error(`[delete-user] PI cancel failed for trade ${t.id}:`, e.message));
        }
      }
      // Remove user's data.
      db.prepare('DELETE FROM notifications WHERE user_id=?').run(userId);
      db.prepare('DELETE FROM reviews WHERE author_id=? OR subject_id=?').run(userId, userId);
      db.prepare('DELETE FROM friendships WHERE requester_id=? OR recipient_id=?').run(userId, userId);
      db.prepare('DELETE FROM messages WHERE sender_id=?').run(userId);
      db.prepare('DELETE FROM offers WHERE from_user_id=? OR to_user_id=?').run(userId, userId);
      db.prepare('DELETE FROM listings WHERE owner_id=?').run(userId);
      db.prepare('DELETE FROM disputes WHERE filed_by_id=?').run(userId);
      db.prepare('DELETE FROM payments WHERE user_id=?').run(userId);
      db.prepare('DELETE FROM users WHERE id=?').run(userId);
    });
    tx();
    console.log(`[account-deletion] user ${userId} (${handle}) deleted`);
    res.clearCookie('rr_token');
    res.json({ ok: true, deleted: handle });
  } catch (e) {
    console.error('[account-deletion] failed:', e.message);
    res.status(500).json({ error: 'could not delete account: ' + e.message });
  }
});

// ===== HEALTH =====
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// ===== ERROR HANDLING =====
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'server error', message: err.message });
});

app.listen(PORT, () => console.log(`Ribbon Reflector API listening on :${PORT}`));
