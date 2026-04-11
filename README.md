# Ribbon Reflector — Backend

Express + SQLite API for a fan-to-fan, face-value-only concert ticket trading site.

## Stack

- **Express** — HTTP server
- **better-sqlite3** — synchronous SQLite driver (fast, simple, zero config)
- **bcryptjs** — password hashing
- **jsonwebtoken** — stateless auth via httpOnly cookies
- **Mock Stripe** — charge/refund functions that log instead of hitting the real API. Swap for `stripe` SDK calls in production.

## Setup

```bash
cd backend
npm install
npm run seed    # wipes + seeds test data
npm start       # runs on :3001
```

Test user after seeding:
- Email: `folkjam@fan.co`
- Password: `password123`
- All seed users have the same password.

## Schema

Nine tables in `schema.sql`: `users`, `listings`, `offers`, `trades`, `messages`, `disputes`, `reviews`, `payments`, `notifications`. Foreign keys enforced; indexes on hot paths (listings.status, offers.to_user_id, messages.trade_id, reviews.subject_id).

### Key state transitions

```
listing:  pending → active → traded
          (moderator approves after receipt review)

offer:    pending → accepted → [trade created]
                  → declined
                  → withdrawn

trade:    active → complete      (both a_received AND b_received = 1)
                 → disputed      (file dispute)
                 → cancelled     (admin resolution)
```

### Escrow logic

When an offer is accepted, the server:
1. Creates a trade row
2. Mock-charges both users `(target_face + offered_face) * 100` cents (covers a refund buffer)
3. Writes two `escrow_hold` payment rows
4. Marks both listings as `traded`
5. Auto-declines any other pending offers on those listings
6. All of this is wrapped in a `db.transaction()` for atomicity

Funds are released when both parties have marked their side as received — the server writes two `escrow_release` payment rows and sets the trade to `complete`. Real Stripe flow would use PaymentIntents with manual capture, then `paymentIntent.capture()` on release.

## Endpoints

### Auth
| Method | Path | Notes |
|---|---|---|
| POST | `/api/auth/signup` | `{handle, email, password, bio}` — sets httpOnly cookie |
| POST | `/api/auth/login` | `{email, password}` |
| POST | `/api/auth/logout` | Clears cookie |
| GET  | `/api/me` | Returns current user |

### Membership
| Method | Path | Notes |
|---|---|---|
| POST | `/api/checkout/membership` | Mock-charges $10, sets `is_member=1`, `member_until=now+1yr` |

### Listings
| Method | Path | Notes |
|---|---|---|
| GET  | `/api/listings?q=&city=&max_price=&sort=&owner=` | Active only, filtered |
| GET  | `/api/listings/:id` | One listing |
| POST | `/api/listings` | Member required. `receipt_filename` required. Auto-approves after 2s (stand-in for moderation) |
| GET  | `/api/events/:key` | `key = artist\|venue\|event_date` (URL-encode the pipes) |

### Profiles
| GET | `/api/users/:handle` | Listings, reviews, trust score |

### Offers
| Method | Path | Notes |
|---|---|---|
| POST | `/api/offers` | `{target_listing_id, offered_listing_id, note}`. Validates ownership |
| GET  | `/api/offers/incoming` | Offers to me, with both listing details joined |
| GET  | `/api/offers/outgoing` | Offers I sent |
| POST | `/api/offers/:id/accept` | Charges both, creates trade, auto-declines competing offers |
| POST | `/api/offers/:id/decline` | |

### Trades
| Method | Path | Notes |
|---|---|---|
| GET  | `/api/trades/:id` | Full trade detail with both listings joined |
| POST | `/api/trades/:id/mark-sent` | Marks your side sent |
| POST | `/api/trades/:id/mark-received` | Marks your side received; completes + releases escrow if both sides done |
| POST | `/api/trades/:id/dispute` | `{reason, details, evidence_filename}` — sets trade.status='disputed' |

### Messages
| GET  | `/api/trades/:id/messages` |
| POST | `/api/trades/:id/messages` | `{body}` |

### Reviews
| POST | `/api/reviews` | `{trade_id, stars, body}`. Only allowed on completed trades |

### Notifications
| GET  | `/api/notifications` |
| POST | `/api/notifications/:id/read` |
| POST | `/api/notifications/read-all` |

## curl quickstart

```bash
# Sign up
curl -c cookies.txt -H 'Content-Type: application/json' \
  -d '{"handle":"newbie","email":"new@fan.co","password":"password123"}' \
  http://localhost:3001/api/auth/signup

# Join (mock pay $10)
curl -b cookies.txt -X POST http://localhost:3001/api/checkout/membership

# Browse listings
curl 'http://localhost:3001/api/listings?q=phish&max_price=200'

# Make an offer (requires owning a listing first — post one)
curl -b cookies.txt -H 'Content-Type: application/json' \
  -d '{"artist":"Goose","venue":"Brooklyn Paramount","face_value":95,"receipt_filename":"r.pdf"}' \
  http://localhost:3001/api/listings

# Send an offer
curl -b cookies.txt -H 'Content-Type: application/json' \
  -d '{"target_listing_id":1,"offered_listing_id":6,"note":"Trade?"}' \
  http://localhost:3001/api/offers
```

## Production hardening checklist

This is a scaffold, not production-ready. Before going live:

1. **Real Stripe** — replace `mockStripeCharge`/`mockStripeRefund` with `stripe.paymentIntents.create({capture_method:'manual'})` and `paymentIntent.capture()` on release. Use Stripe Connect for payouts between users.
2. **Face-value verification** — receipt upload currently records a filename. Add real S3 upload, then either a human moderator queue or an API check against Ticketmaster/AXS order lookup.
3. **Moderation queue** — the 2-second auto-approve in `POST /api/listings` is a demo stand-in. Replace with admin dashboard + reviewer role.
4. **Secrets** — move `JWT_SECRET` and Stripe keys to env vars (`.env` + `dotenv`). Never commit them.
5. **Rate limiting** — add `express-rate-limit` on `/api/auth/*` and `/api/offers`.
6. **Input validation** — add `zod` schemas on every POST body.
7. **WebSockets** — chat currently polls via GET. Add `socket.io` for real-time messaging and typing indicators.
8. **Email/SMS** — notifications only go to the in-app bell. Wire `resend` or `postmark` for transactional email, `twilio` for SMS on critical events (offer accepted, ticket sent).
9. **Legal** — ticket resale law varies by state. Add TOS, privacy policy, and a jurisdiction check on signup. NY and CA have specific rules; research before launch.
10. **Receipt file storage** — currently only the filename is stored. Store files in S3 with signed URLs; scan uploads for malware.
11. **Postgres migration** — SQLite is fine to 10k users. Beyond that, migrate to Postgres (schema should port cleanly; drop WAL pragma, adjust `AUTOINCREMENT` → `SERIAL`).
12. **CORS** — currently `origin: true` for dev. Lock to your frontend domain in prod.
13. **Tests** — add Vitest or Jest; the escrow flow especially needs tests (concurrent offers, race conditions on `accept`).

## Wiring to the existing frontend

The frontend currently uses an in-memory `store` object in `app.js`. To connect it to this backend:

1. Replace `store` mutations with `fetch` calls (keep `credentials: 'include'` so cookies flow)
2. Turn pure renderers into async — load data in a per-route hook, then `render()`
3. Add a small API client (`api.js`) with typed helpers: `api.listings.list()`, `api.offers.accept(id)`, etc.
4. Replace `store.activeTrade` with a `currentTradeId` that refetches on mount

That rewiring is a separate project — the existing prototype still runs standalone if you open `index.html` directly.
