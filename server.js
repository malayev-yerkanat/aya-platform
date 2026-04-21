/**
 * Kórseteıik – Authentication Server
 * Pure Node.js · zero npm dependencies
 *
 * Storage : korseteik.db.json  (JSON flat-file database)
 * Crypto  : PBKDF2-SHA512 password hashing (built-in crypto)
 * Tokens  : HMAC-SHA256 JWT (hand-rolled, spec-compliant)
 *
 * Endpoints
 *   POST /api/register   – create account
 *   POST /api/login      – verify credentials → JWT
 *   GET  /api/me         – return current user (requires Bearer token)
 *   GET  /*              – serve korseteik-prototype.html
 */

'use strict';

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

// ─── CONFIG ─────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'korseteik_secret_2025_change_in_prod';
const DB_FILE    = path.join(__dirname, 'korseteik.db.json');
const HTML_FILE  = path.join(__dirname, 'korseteik-prototype.html');

// ─── FLAT-FILE DATABASE ──────────────────────────────────────────────────────
function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], nextId: 1 }, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// ─── PASSWORD HASHING (PBKDF2) ───────────────────────────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100_000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const attempt = crypto.pbkdf2Sync(password, salt, 100_000, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(attempt, 'hex'));
}

// ─── JWT (HMAC-SHA256) ────────────────────────────────────────────────────────
function b64url(str) {
  return Buffer.from(str).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function makeJWT(payload) {
  const header  = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body    = b64url(JSON.stringify({ ...payload, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + 60*60*24*30 }));
  const sig     = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}
function verifyJWT(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp < Math.floor(Date.now()/1000)) return null;
    return payload;
  } catch { return null; }
}

// ─── HTTP HELPERS ────────────────────────────────────────────────────────────
function json(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type':  'application/json',
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}
function safeUser(user) {
  const { password_hash, ...safe } = user;
  return safe;
}

// ─── ROUTER ──────────────────────────────────────────────────────────────────
async function router(req, res) {
  const url    = req.url.split('?')[0];
  const method = req.method.toUpperCase();

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    });
    return res.end();
  }

  // ── POST /api/register ────────────────────────────────────────────────────
  if (method === 'POST' && url === '/api/register') {
    let body;
    try { body = await readBody(req); }
    catch { return json(res, 400, { error: 'Invalid JSON' }); }

    const { first_name, last_name, email, password, role = 'viewer' } = body;

    if (!first_name || !last_name || !email || !password)
      return json(res, 400, { error: 'All fields are required' });
    if (password.length < 6)
      return json(res, 400, { error: 'Password must be at least 6 characters' });
    if (!['viewer','creator','studio'].includes(role))
      return json(res, 400, { error: 'Invalid role' });

    const db = readDB();
    const exists = db.users.find(u => u.email.toLowerCase() === email.toLowerCase().trim());
    if (exists) return json(res, 409, { error: 'Email already registered' });

    const user = {
      id:            db.nextId++,
      first_name:    first_name.trim(),
      last_name:     last_name.trim(),
      email:         email.trim().toLowerCase(),
      password_hash: hashPassword(password),
      role,
      avatar_url:    null,
      created_at:    new Date().toISOString()
    };

    db.users.push(user);
    writeDB(db);

    const token = makeJWT({ id: user.id, email: user.email, role: user.role });
    return json(res, 201, { token, user: safeUser(user) });
  }

  // ── POST /api/login ───────────────────────────────────────────────────────
  if (method === 'POST' && url === '/api/login') {
    let body;
    try { body = await readBody(req); }
    catch { return json(res, 400, { error: 'Invalid JSON' }); }

    const { email, password } = body;
    if (!email || !password) return json(res, 400, { error: 'Email and password required' });

    const db   = readDB();
    const user = db.users.find(u => u.email === email.trim().toLowerCase());
    if (!user) return json(res, 401, { error: 'Invalid email or password' });

    const valid = verifyPassword(password, user.password_hash);
    if (!valid) return json(res, 401, { error: 'Invalid email or password' });

    const token = makeJWT({ id: user.id, email: user.email, role: user.role });
    return json(res, 200, { token, user: safeUser(user) });
  }

  // ── GET /api/me ───────────────────────────────────────────────────────────
  if (method === 'GET' && url === '/api/me') {
    const auth  = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return json(res, 401, { error: 'No token provided' });

    const payload = verifyJWT(token);
    if (!payload) return json(res, 401, { error: 'Invalid or expired token' });

    const db   = readDB();
    const user = db.users.find(u => u.id === payload.id);
    if (!user) return json(res, 404, { error: 'User not found' });

    return json(res, 200, { user: safeUser(user) });
  }

  // ── Serve static assets (images, fonts, etc.) ────────────────────────────
  if (method === 'GET' && url.startsWith('/assets/')) {
    const assetPath = path.join(__dirname, url);
    if (fs.existsSync(assetPath)) {
      const ext = path.extname(assetPath).toLowerCase();
      const mimeTypes = {
        '.png':  'image/png',
        '.jpg':  'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif':  'image/gif',
        '.webp': 'image/webp',
        '.svg':  'image/svg+xml',
        '.ico':  'image/x-icon',
        '.woff': 'font/woff',
        '.woff2':'font/woff2',
        '.ttf':  'font/ttf',
        '.css':  'text/css',
        '.js':   'text/javascript',
      };
      const contentType = mimeTypes[ext] || 'application/octet-stream';
      const content = fs.readFileSync(assetPath);
      res.writeHead(200, {
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=31536000',
        'Content-Length': content.length
      });
      return res.end(content);
    }
    res.writeHead(404);
    return res.end('Asset not found');
  }

  // ── Serve static HTML ─────────────────────────────────────────────────────
  if (method === 'GET') {
    if (fs.existsSync(HTML_FILE)) {
      const content = fs.readFileSync(HTML_FILE);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(content);
    }
    res.writeHead(404);
    return res.end('Not found');
  }

  json(res, 404, { error: 'Not found' });
}

// ─── START ───────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try {
    await router(req, res);
  } catch (err) {
    console.error('Unhandled error:', err);
    json(res, 500, { error: 'Internal server error' });
  }
});

server.listen(PORT, () => {
  console.log('');
  console.log('  🎬 Kórseteıik server ready');
  console.log(`  → http://localhost:${PORT}`);
  console.log(`  → Database: ${DB_FILE}`);
  console.log('');
});
