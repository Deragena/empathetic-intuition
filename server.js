'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 8080);
const HOST = '0.0.0.0';
const DB_FILE = path.join(__dirname, 'data.json');
const ADMIN_NAME = String(process.env.HUMSTER_ADMIN || 'creator').toLowerCase();
const ADMIN_PASSWORD = process.env.HUMSTER_ADMIN_PASSWORD || '';
const ADMIN_KEY = process.env.HUMSTER_ADMIN_KEY || '';
const LIMIT = 1_000_000_000;
const MAX_BODY = 16 * 1024;
const sessions = new Map();
const attempts = new Map();

function freshDB() {
  return { users: {}, appeals: [], nextAppeal: 1 };
}

function loadDB() {
  try {
    const d = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!d.users || !Array.isArray(d.appeals)) throw new Error('Invalid DB');
    return d;
  } catch (e) {
    if (e.code !== 'ENOENT') {
      console.error('Cannot read database:', e.message);
      process.exit(1);
    }
    return freshDB();
  }
}

let db = loadDB();

function saveDB() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DB_FILE);
}

function send(res, status, obj) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(JSON.stringify(obj));
}

function fail(res, status, message) {
  send(res, status, { ok: false, error: message });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (Buffer.byteLength(data) > MAX_BODY) {
        reject(new Error('BODY_TOO_LARGE'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        reject(new Error('BAD_JSON'));
      }
    });
    req.on('error', reject);
  });
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function makePassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: hashPassword(password, salt) };
}

function passwordMatches(password, user) {
  const a = Buffer.from(hashPassword(password, user.salt), 'hex');
  const b = Buffer.from(user.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function newUser(name, password, role = 'player') {
  const p = makePassword(password);
  return {
    name,
    salt: p.salt,
    hash: p.hash,
    role,
    coins: 0,
    clickPower: 1,
    income: 0,
    clickCost: 50,
    incomeCost: 200,
    robotCost: 1000,
    clickLevel: 1,
    robotLevel: 0,
    banned: false,
    createdAt: Date.now()
  };
}

if (!ADMIN_PASSWORD || !ADMIN_KEY ||
    ADMIN_PASSWORD.length < 12 || ADMIN_KEY.length < 32) {
  console.error('SET HUMSTER_ADMIN_PASSWORD (12+ chars) AND HUMSTER_ADMIN_KEY (32+ chars).');
  process.exit(1);
}

if (!/^[a-z0-9_]{3,20}$/.test(ADMIN_NAME)) {
  console.error('HUMSTER_ADMIN must be 3-20 letters, numbers or underscores.');
  process.exit(1);
}

if (!db.users[ADMIN_NAME]) {
  db.users[ADMIN_NAME] = newUser(ADMIN_NAME, ADMIN_PASSWORD, 'admin');
  saveDB();
} else {
  db.users[ADMIN_NAME].role = 'admin';
  saveDB();
}

function auth(req) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const s = sessions.get(token);
  if (!s || s.expires < Date.now()) {
    if (token) sessions.delete(token);
    return null;
  }
  const user = db.users[s.name];
  return user || null;
}

function rateLimited(req) {
  const ip = req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const item = attempts.get(ip) || { count: 0, start: now };
  if (now - item.start > 60_000) {
    item.count = 0;
    item.start = now;
  }
  item.count++;
  attempts.set(ip, item);
  return item.count > 120;
}

function publicUser(u) {
  return {
    name: u.name,
    role: u.role,
    coins: u.coins,
    clickPower: u.clickPower,
    income: u.income,
    clickLevel: u.clickLevel,
    robotLevel: u.robotLevel,
    banned: u.banned
  };
}

function banIfNeeded(u) {
  if (u.coins >= LIMIT) {
    u.coins = LIMIT;
    u.banned = true;
  }
}

function requirePlayer(req, res) {
  const u = auth(req);
  if (!u) {
    fail(res, 401, 'Login required');
    return null;
  }
  if (u.banned) {
    fail(res, 403, 'BANNED: contact the creator on Discord');
    return null;
  }
  return u;
}

async function route(req, res) {
  if (rateLimited(req)) return fail(res, 429, 'Too many requests');

  const url = new URL(req.url, 'http://localhost');
  const routePath = url.pathname;
  const method = req.method;

  if (method === 'GET' && routePath === '/api/health') {
    return send(res, 200, { ok: true, service: 'Humster Criminal Original' });
  }

  let body = {};
  if (method !== 'GET') {
    try {
      body = await readBody(req);
    } catch (e) {
      return fail(res, e.message === 'BODY_TOO_LARGE' ? 413 : 400,
        'Invalid request body');
    }
  }

  if (method === 'POST' && routePath === '/api/register') {
    const name = String(body.name || '').toLowerCase();
    const password = String(body.password || '');
    if (!/^[a-z0-9_]{3,20}$/.test(name))
      return fail(res, 400, 'Name: 3-20 letters, numbers or underscores');
    if (password.length < 10 || password.length > 128)
      return fail(res, 400, 'Password must be 10-128 characters');
    if (db.users[name]) return fail(res, 409, 'Name already exists');

    db.users[name] = newUser(name, password);
    saveDB();
    return send(res, 201, { ok: true, message: 'Registered. Please log in.' });
  }

  if (method === 'POST' && routePath === '/api/login') {
    const name = String(body.name || '').toLowerCase();
    const password = String(body.password || '');
    const u = db.users[name];
    if (!u || !passwordMatches(password, u))
      return fail(res, 401, 'Invalid username or password');

    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { name, expires: Date.now() + 7 * 86400000 });
    return send(res, 200, {
      ok: true, token, user: publicUser(u)
    });
  }

  if (method === 'POST' && routePath === '/api/logout') {
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    sessions.delete(token);
    return send(res, 200, { ok: true });
  }

  if (method === 'GET' && routePath === '/api/me') {
    const u = auth(req);
    if (!u) return fail(res, 401, 'Login required');
    return send(res, 200, { ok: true, user: publicUser(u) });
  }

  if (method === 'GET' && routePath === '/api/leaderboard') {
    const players = Object.values(db.users)
      .filter(u => u.role !== 'admin')
      .sort((a, b) => b.coins - a.coins)
      .slice(0, 50)
      .map((u, i) => ({
        rank: i + 1, name: u.name, coins: u.coins, banned: u.banned
      }));
    return send(res, 200, { ok: true, players });
  }

  if (method === 'POST' && routePath === '/api/click') {
    const u = requirePlayer(req, res);
    if (!u) return;
    const amount = Math.max(1, Math.min(20, Number(body.count) || 1));
    u.coins = Math.min(LIMIT, u.coins + u.clickPower * amount);
    banIfNeeded(u);
    saveDB();
    return send(res, 200, {
      ok: true, user: publicUser(u),
      message: u.banned ? 'BANNED' : 'Click accepted'
    });
  }

  if (method === 'POST' && routePath === '/api/upgrade') {
    const u = requirePlayer(req, res);
    if (!u) return;
    const type = String(body.type || '');
    let cost;

    if (type === 'click') {
      cost = u.clickCost;
      if (u.coins < cost) return fail(res, 400, 'Not enough coins');
      u.coins -= cost;
      u.clickPower++;
      u.clickLevel++;
      u.clickCost = Math.min(LIMIT, cost * 2);
    } else if (type === 'income') {
      cost = u.incomeCost;
      if (u.coins < cost) return fail(res, 400, 'Not enough coins');
      u.coins -= cost;
      u.income++;
      u.incomeCost = Math.min(LIMIT, cost * 2);
    } else if (type === 'robot') {
      cost = u.robotCost;
      if (u.coins < cost) return fail(res, 400, 'Not enough coins');
      u.coins -= cost;
      u.clickPower += 25;
      u.robotLevel++;
      u.robotCost = Math.min(LIMIT, cost * 3);
    } else {
      return fail(res, 400, 'Unknown upgrade');
    }

    saveDB();
    return send(res, 200, { ok: true, user: publicUser(u) });
  }

  if (method === 'POST' && routePath === '/api/appeals') {
    const u = auth(req);
    if (!u) return fail(res, 401, 'Login required');
    if (!u.banned) return fail(res, 400, 'You are not banned');

    const existing = db.appeals.find(a =>
      a.name === u.name && a.status === 'pending');
    if (existing) return send(res, 200, {
      ok: true, appeal: existing.id, message: 'Appeal already pending'
    });

    const appeal = {
      id: db.nextAppeal++,
      name: u.name,
      message: String(body.message || 'Please review my ban').slice(0, 500),
      status: 'pending',
      createdAt: Date.now()
    };
    db.appeals.push(appeal);
    saveDB();
    return send(res, 201, { ok: true, appeal: appeal.id });
  }

  if (method === 'POST' && routePath === '/api/admin/appeal') {
    const key = String(req.headers['x-admin-key'] || '');
    const admin = auth(req);
    if (!admin || admin.role !== 'admin' ||
        key.length !== ADMIN_KEY.length ||
        !crypto.timingSafeEqual(Buffer.from(key), Buffer.from(ADMIN_KEY))) {
      return fail(res, 403, 'Creator permission required');
    }

    const id = Number(body.id);
    const decision = String(body.decision || '');
    if (!Number.isSafeInteger(id) ||
        !['unban', 'deny'].includes(decision)) {
      return fail(res, 400, 'Use decision unban or deny and a valid id');
    }

    const appeal = db.appeals.find(a => a.id === id);
    if (!appeal) return fail(res, 404, 'Appeal not found');
    if (appeal.status !== 'pending')
      return fail(res, 409, 'Appeal already decided');

    const player = db.users[appeal.name];
    appeal.status = decision === 'unban' ? 'approved' : 'denied';
    appeal.reviewedAt = Date.now();
    appeal.reviewedBy = admin.name;

    if (player && decision === 'unban') {
      player.banned = false;
      player.coins = Math.min(player.coins, LIMIT - 1);
    }
    saveDB();
    return send(res, 200, { ok: true, appeal });
  }

  if (method === 'GET' && routePath === '/api/admin/appeals') {
    const admin = auth(req);
    const key = String(req.headers['x-admin-key'] || '');
    if (!admin || admin.role !== 'admin' ||
        key.length !== ADMIN_KEY.length ||
        !crypto.timingSafeEqual(Buffer.from(key), Buffer.from(ADMIN_KEY))) {
      return fail(res, 403, 'Creator permission required');
    }
    return send(res, 200, {
      ok: true,
      appeals: db.appeals
    });
  }

  return fail(res, 404, 'Endpoint not found');
}

const server = http.createServer((req, res) => {
  route(req, res).catch(err => {
    console.error(err);
    if (!res.headersSent) fail(res, 500, 'Internal server error');
    else res.destroy();
  });
});

server.listen(PORT, HOST, () => {
  console.log('Humster Criminal Original server running');
  console.log(`Listening on ${HOST}:${PORT}`);
  console.log('Health check: http://127.0.0.1:' + PORT + '/api/health');
  console.log('Creator username:', ADMIN_NAME);
  console.log('Keep the admin password and key private.');
});

function shutdown() {
  saveDB();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 3000).unref();
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
