const express = require('express');
const http = require('http');
const cors = require('cors');

// Autorise ton site frontend en ligne à communiquer avec le serveur
app.use(cors({
  origin: 'https://onrender.com',
  credentials: true
}));

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
if (!process.env.JWT_SECRET) console.warn('⚠️  JWT_SECRET non défini : définis-le dans Render (Environment).');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50kb' }));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

// ---------------------------------------------------------------- Base de données
let pool;
async function initDb() {
  if (process.env.DATABASE_URL) {
    const { Pool } = require('pg');
    const url = process.env.DATABASE_URL;
    const noSsl = process.env.PGSSL === 'disable' || /localhost|127\.0\.0\.1/.test(url);
    pool = new Pool({ connectionString: url, ssl: noSsl ? false : { rejectUnauthorized: false } });
  } else {
    console.warn('⚠️  DATABASE_URL absent : base EN MÉMOIRE (les données sont perdues au redémarrage).');
    const { newDb } = require('pg-mem');
    pool = new (newDb().adapters.createPg().Pool)();
  }
  const schema = [
    `CREATE TABLE IF NOT EXISTS users (
       id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
       password_hash TEXT NOT NULL, permission TEXT NOT NULL DEFAULT 'contacts',
       created_at TIMESTAMPTZ DEFAULT now())`,
    `CREATE TABLE IF NOT EXISTS friendships (
       id SERIAL PRIMARY KEY, requester INTEGER NOT NULL, addressee INTEGER NOT NULL,
       status TEXT NOT NULL DEFAULT 'pending')`,
    `CREATE TABLE IF NOT EXISTS blocks (
       user_id INTEGER NOT NULL, blocked_id INTEGER NOT NULL, PRIMARY KEY (user_id, blocked_id))`,
    `CREATE TABLE IF NOT EXISTS channels (
       id SERIAL PRIMARY KEY, name TEXT NOT NULL, emoji TEXT NOT NULL DEFAULT '💬', owner_id INTEGER)`,
    `CREATE TABLE IF NOT EXISTS messages (
       id SERIAL PRIMARY KEY, kind TEXT NOT NULL, room TEXT NOT NULL, sender_id INTEGER NOT NULL,
       body TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())`,
    `CREATE INDEX IF NOT EXISTS idx_messages_room ON messages (kind, room, id)`,
  ];
  for (const sql of schema) await pool.query(sql);
  const { rows } = await pool.query('SELECT COUNT(*) AS n FROM channels');
  if (Number(rows[0].n) === 0) {
    await pool.query(`INSERT INTO channels (name, emoji) VALUES ('Accueil', '🏠')`);
    await pool.query(`INSERT INTO channels (name, emoji) VALUES ('Gaming', '🎮')`);
  }
}
const q = async (sql, params = []) => (await pool.query(sql, params)).rows;
const one = async (sql, params = []) => (await q(sql, params))[0] || null;

// ---------------------------------------------------------------- Helpers
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const pub = (u) => ({ id: u.id, username: u.username, displayName: u.display_name });
const mine = (u) => ({ ...pub(u), permission: u.permission });
const dmRoom = (a, b) => `${Math.min(a, b)}:${Math.max(a, b)}`;
const getUser = (id) => one('SELECT * FROM users WHERE id = $1', [id]);
const getByName = (name) => one('SELECT * FROM users WHERE username = $1', [String(name || '').trim().toLowerCase()]);
async function usersByIds(ids) {
  if (!ids.length) return [];
  return q(`SELECT * FROM users WHERE id IN (${ids.map((_, i) => '$' + (i + 1)).join(',')})`, ids);
}
const sign = (u) => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '30d' });
const toMsg = (m, senderName) => ({
  id: m.id, kind: m.kind, room: m.room, senderId: m.sender_id, senderName,
  text: m.body, createdAt: m.created_at,
});

async function friendshipBetween(a, b) {
  return one(
    `SELECT * FROM friendships WHERE (requester = $1 AND addressee = $2) OR (requester = $2 AND addressee = $1)`,
    [a, b],
  );
}
async function isBlockedEither(a, b) {
  return one(
    `SELECT 1 AS x FROM blocks WHERE (user_id = $1 AND blocked_id = $2) OR (user_id = $2 AND blocked_id = $1)`,
    [a, b],
  );
}
const ping = (userId, event, payload) => io.to(`user:${userId}`).emit(event, payload);

// Limitation basique des essais (anti brute-force)
const attempts = new Map();
function rateLimit(req, _res, next) {
  const key = req.ip;
  const now = Date.now();
  const list = (attempts.get(key) || []).filter((t) => now - t < 5 * 60 * 1000);
  if (list.length >= 20) throw new HttpError(429, 'Trop de tentatives, réessaie dans quelques minutes.');
  list.push(now);
  attempts.set(key, list);
  next();
}

async function auth(req, _res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) throw new HttpError(401, 'Non connecté.');
  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); } catch { throw new HttpError(401, 'Session expirée.'); }
  const user = await getUser(payload.id);
  if (!user) throw new HttpError(401, 'Compte introuvable.');
  req.user = user;
  next();
}

// ---------------------------------------------------------------- Présence
const online = new Map(); // userId -> nombre de sockets

// ---------------------------------------------------------------- Routes : général / comptes
app.get('/', (_req, res) => res.send('NexusChat backend OK'));
app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/api/register', rateLimit, async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const displayName = String(req.body.displayName || '').trim();
  const password = String(req.body.password || '');
  if (!/^[a-z0-9_]{3,20}$/.test(username)) throw new HttpError(400, 'Identifiant : 3 à 20 caractères (lettres, chiffres, _).');
  if (displayName.length < 1 || displayName.length > 40) throw new HttpError(400, 'Nom affiché : 1 à 40 caractères.');
  if (password.length < 6 || password.length > 100) throw new HttpError(400, 'Mot de passe : 6 caractères minimum.');
  if (await getByName(username)) throw new HttpError(409, "Ce nom d'utilisateur existe déjà.");
  const hash = await bcrypt.hash(password, 10);
  const user = await one(
    'INSERT INTO users (username, display_name, password_hash) VALUES ($1, $2, $3) RETURNING *',
    [username, displayName, hash],
  );
  res.status(201).json({ token: sign(user), user: mine(user) });
});

app.post('/api/login', rateLimit, async (req, res) => {
  const user = await getByName(req.body.username);
  const ok = user && (await bcrypt.compare(String(req.body.password || ''), user.password_hash));
  if (!ok) throw new HttpError(401, 'Identifiant ou mot de passe incorrect.');
  res.json({ token: sign(user), user: mine(user) });
});

app.get('/api/me', auth, (req, res) => res.json({ user: mine(req.user) }));

app.patch('/api/me', auth, async (req, res) => {
  const { displayName, permission } = req.body;
  if (displayName !== undefined) {
    const name = String(displayName).trim();
    if (name.length < 1 || name.length > 40) throw new HttpError(400, 'Nom affiché : 1 à 40 caractères.');
    await q('UPDATE users SET display_name = $1 WHERE id = $2', [name, req.user.id]);
  }
  if (permission !== undefined) {
    if (!['everyone', 'contacts', 'none'].includes(permission)) throw new HttpError(400, 'Permission invalide.');
    await q('UPDATE users SET permission = $1 WHERE id = $2', [permission, req.user.id]);
  }
  res.json({ user: mine(await getUser(req.user.id)) });
});

app.get('/api/users/search', auth, async (req, res) => {
  const term = String(req.query.q || '').trim().toLowerCase().replace(/[%_]/g, '');
  if (term.length < 2) return res.json({ users: [] });
  const rows = await q('SELECT * FROM users WHERE username LIKE $1 AND id <> $2 LIMIT 10', [`${term}%`, req.user.id]);
  res.json({ users: rows.map(pub) });
});

// ---------------------------------------------------------------- Amis
app.get('/api/friends', auth, async (req, res) => {
  const me = req.user.id;
  const rows = await q('SELECT * FROM friendships WHERE requester = $1 OR addressee = $1', [me]);
  const users = await usersByIds([...new Set(rows.map((r) => (r.requester === me ? r.addressee : r.requester)))]);
  const byId = new Map(users.map((u) => [u.id, pub(u)]));
  const other = (r) => byId.get(r.requester === me ? r.addressee : r.requester);
  res.json({
    friends: rows.filter((r) => r.status === 'accepted').map((r) => ({ friendshipId: r.id, user: other(r) })),
    incoming: rows.filter((r) => r.status === 'pending' && r.addressee === me).map((r) => ({ friendshipId: r.id, user: other(r) })),
    outgoing: rows.filter((r) => r.status === 'pending' && r.requester === me).map((r) => ({ friendshipId: r.id, user: other(r) })),
  });
});

app.post('/api/friends/request', auth, async (req, res) => {
  const me = req.user.id;
  const target = await getByName(req.body.username);
  if (!target) throw new HttpError(404, 'Aucun utilisateur avec cet identifiant.');
  if (target.id === me) throw new HttpError(400, "Tu ne peux pas t'ajouter toi-même.");
  if (await isBlockedEither(me, target.id)) throw new HttpError(404, 'Aucun utilisateur avec cet identifiant.');
  const existing = await friendshipBetween(me, target.id);
  if (existing) {
    if (existing.status === 'accepted') throw new HttpError(409, 'Vous êtes déjà amis.');
    if (existing.requester === me) throw new HttpError(409, 'Demande déjà envoyée.');
    await q(`UPDATE friendships SET status = 'accepted' WHERE id = $1`, [existing.id]); // il m'avait déjà demandé
    ping(me, 'friends:update', {}); ping(target.id, 'friends:update', {});
    return res.json({ status: 'accepted' });
  }
  await q('INSERT INTO friendships (requester, addressee) VALUES ($1, $2)', [me, target.id]);
  ping(me, 'friends:update', {}); ping(target.id, 'friends:update', {});
  res.status(201).json({ status: 'pending' });
});

app.post('/api/friends/:id/accept', auth, async (req, res) => {
  const row = await one('SELECT * FROM friendships WHERE id = $1', [Number(req.params.id)]);
  if (!row || row.addressee !== req.user.id || row.status !== 'pending') throw new HttpError(404, 'Demande introuvable.');
  await q(`UPDATE friendships SET status = 'accepted' WHERE id = $1`, [row.id]);
  ping(row.requester, 'friends:update', {}); ping(row.addressee, 'friends:update', {});
  res.json({ ok: true });
});

// Refuser / annuler une demande / retirer un ami
app.delete('/api/friends/:id', auth, async (req, res) => {
  const row = await one('SELECT * FROM friendships WHERE id = $1', [Number(req.params.id)]);
  if (!row || (row.requester !== req.user.id && row.addressee !== req.user.id)) throw new HttpError(404, 'Introuvable.');
  await q('DELETE FROM friendships WHERE id = $1', [row.id]);
  ping(row.requester, 'friends:update', {}); ping(row.addressee, 'friends:update', {});
  res.json({ ok: true });
});

// ---------------------------------------------------------------- Blocages
app.get('/api/blocks', auth, async (req, res) => {
  const rows = await q('SELECT blocked_id FROM blocks WHERE user_id = $1', [req.user.id]);
  res.json({ users: (await usersByIds(rows.map((r) => r.blocked_id))).map(pub) });
});

app.post('/api/blocks/:userId', auth, async (req, res) => {
  const me = req.user.id, other = Number(req.params.userId);
  if (other === me || !(await getUser(other))) throw new HttpError(404, 'Utilisateur introuvable.');
  if (!(await one('SELECT 1 AS x FROM blocks WHERE user_id = $1 AND blocked_id = $2', [me, other]))) {
    await q('INSERT INTO blocks (user_id, blocked_id) VALUES ($1, $2)', [me, other]);
  }
  const f = await friendshipBetween(me, other);
  if (f) await q('DELETE FROM friendships WHERE id = $1', [f.id]);
  ping(me, 'friends:update', {}); ping(other, 'friends:update', {});
  res.json({ ok: true });
});

app.delete('/api/blocks/:userId', auth, async (req, res) => {
  await q('DELETE FROM blocks WHERE user_id = $1 AND blocked_id = $2', [req.user.id, Number(req.params.userId)]);
  res.json({ ok: true });
});

// ---------------------------------------------------------------- Messages privés
app.get('/api/conversations', auth, async (req, res) => {
  const me = req.user.id;
  const rows = await q(
    `SELECT * FROM messages WHERE kind = 'dm' AND (room LIKE $1 OR room LIKE $2) ORDER BY id DESC LIMIT 300`,
    [`${me}:%`, `%:${me}`],
  );
  const partners = [];
  const last = new Map();
  for (const m of rows) {
    const [a, b] = m.room.split(':').map(Number);
    const p = a === me ? b : a;
    if (!last.has(p)) { last.set(p, m); partners.push(p); }
  }
  const users = new Map((await usersByIds(partners)).map((u) => [u.id, u]));
  res.json({
    conversations: partners.filter((p) => users.has(p)).map((p) => ({
      user: pub(users.get(p)),
      last: toMsg(last.get(p), p === last.get(p).sender_id ? users.get(p).display_name : req.user.display_name),
    })),
  });
});

app.get('/api/dm/:userId', auth, async (req, res) => {
  const me = req.user, other = await getUser(Number(req.params.userId));
  if (!other) throw new HttpError(404, 'Utilisateur introuvable.');
  const rows = await q(
    `SELECT * FROM (SELECT * FROM messages WHERE kind = 'dm' AND room = $1 ORDER BY id DESC LIMIT 100) t ORDER BY id ASC`,
    [dmRoom(me.id, other.id)],
  );
  res.json({ messages: rows.map((m) => toMsg(m, m.sender_id === me.id ? me.display_name : other.display_name)) });
});

app.post('/api/dm/:userId', auth, async (req, res) => {
  const me = req.user, other = await getUser(Number(req.params.userId));
  const text = String(req.body.text || '').trim();
  if (!other || other.id === me.id) throw new HttpError(404, 'Utilisateur introuvable.');
  if (!text || text.length > 2000) throw new HttpError(400, 'Message vide ou trop long (2000 max).');
  if (await isBlockedEither(me.id, other.id)) throw new HttpError(403, "Impossible d'envoyer un message à cet utilisateur.");
  if (other.permission === 'none') throw new HttpError(403, "Cet utilisateur n'accepte pas de messages.");
  if (other.permission === 'contacts') {
    const f = await friendshipBetween(me.id, other.id);
    if (!f || f.status !== 'accepted') throw new HttpError(403, "Cet utilisateur n'accepte que les messages de ses amis. Envoie-lui une demande d'ami.");
  }
  const row = await one(
    `INSERT INTO messages (kind, room, sender_id, body) VALUES ('dm', $1, $2, $3) RETURNING *`,
    [dmRoom(me.id, other.id), me.id, text],
  );
  const msg = toMsg(row, me.display_name);
  ping(me.id, 'dm:new', msg);
  ping(other.id, 'dm:new', msg);
  res.status(201).json({ message: msg });
});

// ---------------------------------------------------------------- Salons
app.get('/api/channels', auth, async (_req, res) => {
  const rows = await q('SELECT * FROM channels ORDER BY id ASC');
  res.json({ channels: rows.map((c) => ({ id: c.id, name: c.name, emoji: c.emoji })) });
});

app.post('/api/channels', auth, async (req, res) => {
  const name = String(req.body.name || '').trim();
  const emoji = String(req.body.emoji || '💬').slice(0, 8);
  if (name.length < 1 || name.length > 30) throw new HttpError(400, 'Nom du salon : 1 à 30 caractères.');
  const c = await one('INSERT INTO channels (name, emoji, owner_id) VALUES ($1, $2, $3) RETURNING *', [name, emoji, req.user.id]);
  const channel = { id: c.id, name: c.name, emoji: c.emoji };
  io.emit('channel:created', channel);
  res.status(201).json({ channel });
});

app.get('/api/channels/:id/messages', auth, async (req, res) => {
  const id = String(Number(req.params.id));
  const rows = await q(
    `SELECT * FROM (SELECT * FROM messages WHERE kind = 'channel' AND room = $1 ORDER BY id DESC LIMIT 100) t ORDER BY id ASC`,
    [id],
  );
  const users = new Map((await usersByIds([...new Set(rows.map((m) => m.sender_id))])).map((u) => [u.id, u.display_name]));
  res.json({ messages: rows.map((m) => toMsg(m, users.get(m.sender_id) || '?')) });
});

app.post('/api/channels/:id/messages', auth, async (req, res) => {
  const channel = await one('SELECT * FROM channels WHERE id = $1', [Number(req.params.id)]);
  const text = String(req.body.text || '').trim();
  if (!channel) throw new HttpError(404, 'Salon introuvable.');
  if (!text || text.length > 2000) throw new HttpError(400, 'Message vide ou trop long (2000 max).');
  const row = await one(
    `INSERT INTO messages (kind, room, sender_id, body) VALUES ('channel', $1, $2, $3) RETURNING *`,
    [String(channel.id), req.user.id, text],
  );
  const msg = toMsg(row, req.user.display_name);
  io.emit('channel:new', msg);
  res.status(201).json({ message: msg });
});

// ---------------------------------------------------------------- Erreurs
app.use((err, _req, res, _next) => {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: 'Erreur du serveur.' });
});

// ---------------------------------------------------------------- Socket.IO (temps réel)
io.use(async (socket, next) => {
  try {
    const payload = jwt.verify(socket.handshake.auth?.token || '', JWT_SECRET);
    const user = await getUser(payload.id);
    if (!user) return next(new Error('unauthorized'));
    socket.userId = user.id;
    next();
  } catch { next(new Error('unauthorized')); }
});

io.on('connection', (socket) => {
  const id = socket.userId;
  socket.join(`user:${id}`);
  online.set(id, (online.get(id) || 0) + 1);
  socket.emit('presence:list', [...online.keys()]);
  if (online.get(id) === 1) io.emit('presence:update', { userId: id, online: true });
  socket.on('disconnect', () => {
    const n = (online.get(id) || 1) - 1;
    if (n <= 0) { online.delete(id); io.emit('presence:update', { userId: id, online: false }); }
    else online.set(id, n);
  });
});

initDb()
  .then(() => server.listen(PORT, '0.0.0.0', () => console.log(`NexusChat backend actif sur le port ${PORT}`)))
  .catch((e) => { console.error('Échec init base de données :', e); process.exit(1); });
