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
// ===== APP =====
const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());
const ALLOWED_ORIGINS = [
  'https://ribbon-reflector-frontend.vercel.app',
  'http://localhost:3000',
  'http://localhost:5173',
];
app.use(cors({
  origin: (origin, cb) => {
    // Allow same-origin/server-to-server (no origin header) and any vercel preview deployments
    if (!origin || ALLOWED_ORIGINS.includes(origin) || /^https:\/\/ribbon-reflector-frontend.*\.vercel\.app$/.test(origin)) {
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
    const user = db.prepare('SELECT id, handle, email, is_member, member_until, bio FROM users WHERE id = ?').get(payload.userId);
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

// ===== NOTIFICATIONS HELPER =====
function notify(userId, icon, text, route, params) {
  db.prepare('INSERT INTO notifications (user_id, icon, text, route, params) VALUES (?, ?, ?, ?, ?)')
    .run(userId, icon, text, route || null, params ? JSON.stringify(params) : null);
}

// ===== AUTH =====
app.post('/api/auth/signup', (req, res) => {
  const { handle, email, password, bio } = req.body;
  if (!handle || !email || !password) return res.status(400).json({ error: 'missing fields' });
  if (password.length < 8) return res.status(400).json({ error: 'password must be at least 8 chars' });
  const normHandle = handle.startsWith('@') ? handle : '@' + handle;
  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare('INSERT INTO users (handle, email, password_hash, bio) VALUES (?, ?, ?, ?)')
      .run(normHandle, email, hash, bio || '');
    const token = makeToken(result.lastInsertRowid);
    res.json({ id: result.lastInsertRowid, handle: normHandle, email, is_member: 0, token });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'handle or email already taken' });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  const token = makeToken(user.id);
  res.json({ id: user.id, handle: user.handle, email: user.email, is_member: user.is_member, member_until: user.member_until, token });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('rr_token');
  res.json({ ok: true });
});

app.get('/api/me', authRequired, (req, res) => res.json(req.user));

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
  let sql = owner
    ? `SELECT l.*, u.handle AS owner_handle FROM listings l JOIN users u ON u.id = l.owner_id WHERE 1=1`
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

app.post('/api/listings', authRequired, memberRequired, (req, res) => {
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
app.get('/api/users/:handle', (req, res) => {
  const handle = req.params.handle.startsWith('@') ? req.params.handle : '@' + req.params.handle;
  const user = db.prepare('SELECT id, handle, bio, created_at FROM users WHERE handle = ?').get(handle);
  if (!user) return res.status(404).json({ error: 'not found' });
  const listings = db.prepare(`SELECT * FROM listings WHERE owner_id=? AND status='active'`).all(user.id);
  const reviews = db.prepare(`SELECT r.*, u.handle AS author_handle FROM reviews r JOIN users u ON u.id=r.author_id WHERE r.subject_id=? ORDER BY r.created_at DESC`).all(user.id);
  const avgRow = db.prepare('SELECT AVG(stars) AS avg, COUNT(*) AS n FROM reviews WHERE subject_id=?').get(user.id);
  res.json({ user, listings, reviews, trust_score: avgRow.n ? Math.round((avgRow.avg/5)*100) : 0, reviews_count: avgRow.n });
});

// ===== OFFERS (cash-only, one-directional) =====
// Buyer makes a cash offer from $0.01 up to (never above) the target listing's face_value.
// amount_cents is authoritative and enforced server-side; frontend cap is a courtesy only.
app.post('/api/offers', authRequired, memberRequired, (req, res) => {
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
  res.json(db.prepare(`SELECT o.*, u.handle AS to_handle,
    tl.artist AS target_artist, tl.venue AS target_venue
    FROM offers o JOIN users u ON u.id=o.to_user_id
    JOIN listings tl ON tl.id=o.target_listing_id
    WHERE o.from_user_id=? ORDER BY o.created_at DESC`).all(req.user.id));
});

// Accept an offer (cash-mode): charge buyer for amount_cents, create trade, mark listing traded, auto-decline siblings.
// Seller is the acceptor (offer.to_user_id); buyer is offer.from_user_id.
app.post('/api/offers/:id/accept', authRequired, (req, res) => {
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

    const tradeResult = db.prepare(`INSERT INTO trades
      (offer_id, buyer_id, seller_id, listing_id, amount_cents, escrow_charge_id)
      VALUES (?,?,?,?,?,?)`)
      .run(offer.id, buyerId, sellerId, listing.id, amountCents, charge.id);

    db.prepare(`UPDATE listings SET status='traded' WHERE id=?`).run(listing.id);

    db.prepare(`INSERT INTO payments (user_id, kind, amount_cents, stripe_id, trade_id) VALUES (?, 'escrow_hold', ?, ?, ?)`)
      .run(buyerId, amountCents, charge.id, tradeResult.lastInsertRowid);

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
  notify(buyerId,  '🎉', `<strong>${req.user.handle}</strong> accepted your ${amountDisplay} offer for ${listing.artist}!`, 'wallet');
  notify(sellerId, '🎉', `You accepted <strong>@${buyerHandle}</strong>'s ${amountDisplay} offer. Send the ticket next.`, 'wallet');
  for (const sib of siblings) {
    notify(sib.from_user_id, '📪', `Your offer on ${listing.artist} was auto-declined because another offer was accepted.`, 'myTickets', { tab: 'outgoing' });
  }

  res.json({ trade_id: tradeId });
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
app.get('/api/trades/:id', authRequired, (req, res) => {
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
app.post('/api/trades/:id/mark-sent', authRequired, (req, res) => {
  const trade = db.prepare('SELECT * FROM trades WHERE id=?').get(req.params.id);
  if (!trade) return res.status(404).json({ error: 'not found' });
  if (trade.status !== 'active') return res.status(400).json({ error: 'trade is ' + trade.status });
  if (trade.seller_id !== req.user.id) return res.status(403).json({ error: 'only the seller can mark sent' });
  if (trade.seller_sent) return res.status(400).json({ error: 'already marked sent' });

  db.prepare(`UPDATE trades SET seller_sent=1 WHERE id=?`).run(trade.id);
  maybeCompleteTrade(trade.id);
  const after = db.prepare('SELECT * FROM trades WHERE id=?').get(trade.id);
  if (after.status === 'active') {
    notify(trade.buyer_id, '✈️', 'Seller marked the ticket as sent. Confirm when you receive it.', 'wallet');
  }
  res.json(after);
});

app.post('/api/trades/:id/mark-received', authRequired, (req, res) => {
  const trade = db.prepare('SELECT * FROM trades WHERE id=?').get(req.params.id);
  if (!trade) return res.status(404).json({ error: 'not found' });
  if (trade.status !== 'active') return res.status(400).json({ error: 'trade is ' + trade.status });
  if (trade.buyer_id !== req.user.id) return res.status(403).json({ error: 'only the buyer can mark received' });
  if (trade.buyer_received) return res.status(400).json({ error: 'already marked received' });
  if (!trade.seller_sent) return res.status(400).json({ error: 'seller has not marked the ticket sent yet' });

  db.prepare(`UPDATE trades SET buyer_received=1 WHERE id=?`).run(trade.id);
  maybeCompleteTrade(trade.id);
  const after = db.prepare('SELECT * FROM trades WHERE id=?').get(trade.id);
  res.json(after);
});

// Finalize trade + release escrow to seller if both sides are marked.
// Idempotent: safe to call repeatedly; only acts once when state transitions.
function maybeCompleteTrade(tradeId) {
  const t = db.prepare('SELECT * FROM trades WHERE id=?').get(tradeId);
  if (!t || t.status !== 'active') return;
  if (!t.seller_sent || !t.buyer_received) return;

  const tx = db.transaction(() => {
    db.prepare(`UPDATE trades SET status='complete', completed_at=CURRENT_TIMESTAMP WHERE id=?`).run(t.id);
    const hold = db.prepare(`SELECT * FROM payments WHERE trade_id=? AND kind='escrow_hold'`).get(t.id);
    const releaseStripeId = hold ? 'rel_' + hold.stripe_id : 'rel_unknown_' + t.id;
    db.prepare(`INSERT INTO payments (user_id, kind, amount_cents, stripe_id, trade_id) VALUES (?, 'escrow_release', ?, ?, ?)`)
      .run(t.seller_id, t.amount_cents, releaseStripeId, t.id);
  });
  tx();

  notify(t.buyer_id,  '✓', 'Trade complete — enjoy the show! Leave a review when you can.', 'reviews');
  notify(t.seller_id, '✓', 'Trade complete — escrow released to you. Leave a review for the buyer.', 'reviews');
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
  res.json({ ok: true });
});

// ===== REVIEWS =====
app.post('/api/reviews', authRequired, (req, res) => {
  const { trade_id, stars, body } = req.body;
  if (!trade_id || !stars) return res.status(400).json({ error: 'trade_id and stars required' });
  const trade = db.prepare('SELECT * FROM trades WHERE id=?').get(trade_id);
  if (!trade) return res.status(404).json({ error: 'trade not found' });
  if (trade.buyer_id !== req.user.id && trade.seller_id !== req.user.id) return res.status(403).json({ error: 'not your trade' });
  if (trade.status !== 'complete') return res.status(400).json({ error: 'can only review completed trades' });
  const subject = trade.buyer_id === req.user.id ? trade.seller_id : trade.buyer_id;
  const result = db.prepare('INSERT INTO reviews (trade_id, author_id, subject_id, stars, body) VALUES (?,?,?,?,?)')
    .run(trade_id, req.user.id, subject, stars, body || '');
  notify(subject, '⭐', `<strong>${req.user.handle}</strong> left you a ${stars}-star review.`, 'profile', { handle: db.prepare('SELECT handle FROM users WHERE id=?').get(subject).handle });
  res.json({ id: result.lastInsertRowid });
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

// ===== HEALTH =====
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// ===== ERROR HANDLING =====
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'server error', message: err.message });
});

app.listen(PORT, () => console.log(`Ribbon Reflector API listening on :${PORT}`));
