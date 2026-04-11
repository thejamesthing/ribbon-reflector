// Seed script — creates test users and listings. Run: node seed.js
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const fs = require('fs'); const path = require('path');

const db = new Database(path.join(__dirname, 'data.db'));
db.exec(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));

// Wipe existing data (preserve structure)
['reviews','disputes','messages','payments','notifications','trades','offers','listings','users'].forEach(t => db.prepare(`DELETE FROM ${t}`).run());

const pw = bcrypt.hashSync('password123', 10);
const users = [
  { handle:'@folkjam',     email:'folkjam@fan.co',     bio:'Phish tour lifer. Always down to trade.' },
  { handle:'@marisol_k',   email:'marisol@fan.co',     bio:'Following Phish up and down the east coast since \'19.' },
  { handle:'@jordan_hifi', email:'jordan@fan.co',      bio:'Vinyl collector, indie concerts, hot takes.' },
  { handle:'@peach.pit',   email:'peach@fan.co',       bio:'NYC-based. Always down for a jam band trade.' },
  { handle:'@ssun.room',   email:'ssun@fan.co',        bio:'West coast psych rock enjoyer.' },
];
const userIds = {};
for (const u of users) {
  const r = db.prepare('INSERT INTO users (handle, email, password_hash, bio, is_member, member_until) VALUES (?,?,?,?,1,?)')
    .run(u.handle, u.email, pw, u.bio, '2027-04-11');
  userIds[u.handle] = r.lastInsertRowid;
}

const listings = [
  { owner:'@marisol_k',   artist:'Phish',         venue:'Hampton Coliseum',       city:'Hampton, VA',   event_date:'2026-09-20', seat:'GA Floor',      qty:1, face_value:120, source:'Ticketmaster' },
  { owner:'@jordan_hifi', artist:'Phish',         venue:'Madison Square Garden',  city:'New York, NY',  event_date:'2026-12-28', seat:'Sec 114 Row 8', qty:1, face_value:250, source:'Ticketmaster' },
  { owner:'@peach.pit',   artist:'Goose',         venue:'Radio City Music Hall',  city:'New York, NY',  event_date:'2026-10-09', seat:'Orch Row M',    qty:1, face_value:185, source:'AXS' },
  { owner:'@ssun.room',   artist:'King Gizzard',  venue:'The Rady Shell',         city:'San Diego, CA', event_date:'2026-08-11', seat:'Sec MARLFT',    qty:2, face_value:165, source:'AXS' },
  { owner:'@folkjam',     artist:'Goose',         venue:'Brooklyn Paramount',     city:'Brooklyn, NY',  event_date:'2026-11-08', seat:'GA Floor',      qty:1, face_value:95,  source:'Ticketmaster' },
];
for (const l of listings) {
  db.prepare(`INSERT INTO listings (owner_id, artist, venue, city, event_date, seat, qty, face_value, source, receipt_filename, status)
    VALUES (?,?,?,?,?,?,?,?,?,?,'active')`)
    .run(userIds[l.owner], l.artist, l.venue, l.city, l.event_date, l.seat, l.qty, l.face_value, l.source, 'seed_receipt.pdf');
}

// Seed a few reviews
const reviews = [
  { author:'@jordan_hifi', subject:'@marisol_k', stars:5, body:'Smooth trade, super fast transfer.' },
  { author:'@peach.pit',   subject:'@marisol_k', stars:5, body:'Fan community at its best.' },
  { author:'@marisol_k',   subject:'@jordan_hifi', stars:5, body:'Great communicator. Would trade again.' },
];
for (const r of reviews) {
  db.prepare('INSERT INTO reviews (author_id, subject_id, stars, body) VALUES (?,?,?,?)')
    .run(userIds[r.author], userIds[r.subject], r.stars, r.body);
}

console.log('✓ Seeded. Login with email: folkjam@fan.co · password: password123');
