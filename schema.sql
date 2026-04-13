-- Ribbon Reflector schema
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  handle TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  bio TEXT,
  is_member INTEGER DEFAULT 0,
  member_until TEXT,
  stripe_customer_id TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS listings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL REFERENCES users(id),
  artist TEXT NOT NULL,
  venue TEXT NOT NULL,
  city TEXT,
  event_date TEXT,
  seat TEXT,
  qty INTEGER DEFAULT 1,
  face_value REAL NOT NULL,
  source TEXT,
  notes TEXT,
  receipt_filename TEXT,
  status TEXT DEFAULT 'pending', -- pending | active | traded | withdrawn
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_listings_status ON listings(status);
CREATE INDEX IF NOT EXISTS idx_listings_artist ON listings(artist);
CREATE INDEX IF NOT EXISTS idx_listings_owner ON listings(owner_id);

-- offers: cash-only, one-directional. Buyer offers amount_cents up to target listing's face_value.
-- amount_cents is authoritative; frontend converts to/from dollars for display.
CREATE TABLE IF NOT EXISTS offers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_user_id INTEGER NOT NULL REFERENCES users(id),
  to_user_id INTEGER NOT NULL REFERENCES users(id),
  target_listing_id INTEGER NOT NULL REFERENCES listings(id),
  amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
  note TEXT,
  status TEXT DEFAULT 'pending', -- pending | accepted | declined | withdrawn
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_offers_to ON offers(to_user_id, status);
CREATE INDEX IF NOT EXISTS idx_offers_from ON offers(from_user_id, status);
CREATE INDEX IF NOT EXISTS idx_offers_target ON offers(target_listing_id, status);

-- trades: cash-mode, one-directional. Buyer pays at accept, seller sends ticket, buyer confirms receipt, escrow releases to seller.
CREATE TABLE IF NOT EXISTS trades (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  offer_id INTEGER NOT NULL REFERENCES offers(id),
  buyer_id INTEGER NOT NULL REFERENCES users(id),
  seller_id INTEGER NOT NULL REFERENCES users(id),
  listing_id INTEGER NOT NULL REFERENCES listings(id),
  amount_cents INTEGER NOT NULL,
  escrow_charge_id TEXT,
  seller_sent INTEGER DEFAULT 0,
  buyer_received INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active', -- active | disputed | complete | cancelled
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_trades_buyer ON trades(buyer_id, status);
CREATE INDEX IF NOT EXISTS idx_trades_seller ON trades(seller_id, status);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  trade_id INTEGER NOT NULL REFERENCES trades(id),
  sender_id INTEGER NOT NULL REFERENCES users(id),
  body TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_messages_trade ON messages(trade_id, created_at);

CREATE TABLE IF NOT EXISTS disputes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  trade_id INTEGER NOT NULL REFERENCES trades(id),
  filed_by_id INTEGER NOT NULL REFERENCES users(id),
  reason TEXT NOT NULL,
  details TEXT,
  evidence_filename TEXT,
  status TEXT DEFAULT 'open', -- open | resolved | rejected
  resolution TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  trade_id INTEGER REFERENCES trades(id),
  author_id INTEGER NOT NULL REFERENCES users(id),
  subject_id INTEGER NOT NULL REFERENCES users(id),
  stars INTEGER NOT NULL CHECK (stars BETWEEN 1 AND 5),
  body TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_reviews_subject ON reviews(subject_id);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL, -- membership | escrow_hold | escrow_release | refund
  amount_cents INTEGER NOT NULL,
  stripe_id TEXT,
  trade_id INTEGER REFERENCES trades(id),
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  icon TEXT,
  text TEXT NOT NULL,
  route TEXT,
  params TEXT,
  is_read INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
