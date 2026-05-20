/**
 * Kórseteıik – Authentication Server
 * Pure Node.js · zero npm dependencies
 *
 * Storage : korseteik.db.json  (JSON flat-file database)
 * Crypto  : PBKDF2-SHA512 password hashing (built-in crypto)
 * Tokens  : HMAC-SHA256 JWT (hand-rolled, spec-compliant)
 *
 * Endpoints
 *   POST   /api/register       – create account
 *   POST   /api/login          – verify credentials → JWT
 *   GET    /api/me             – return current user (requires Bearer token)
 *   GET    /api/content        – list all content items
 *   POST   /api/content        – publish a new content item
 *   DELETE /api/content/:id    – remove a content item (deleteToken required)
 *   GET    /assets/*           – serve static assets with long-term cache
 *   GET    /*                  – serve aya-platform.html
 */

'use strict';

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

// ─── CONSTANTS ───────────────────────────────────────────────────────────────

const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'korseteik_secret_2025_change_in_prod';
const DB_FILE    = path.join(__dirname, 'korseteik.db.json');
const HTML_FILE  = path.join(__dirname, 'aya-platform.html');

const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_KEY_BYTES  = 64;
const SALT_BYTES        = 16;
const JWT_TTL_SECONDS   = 60 * 60 * 24 * 30; // 30 days
const MAX_BODY_BYTES    = 64 * 1024;           // 64 KB — guard against oversized payloads

const VALID_ROLES = new Set(['viewer', 'creator', 'studio']);

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** MIME types for static asset serving — built once at module load. */
const MIME_TYPES = new Map([
  ['.png',  'image/png'],
  ['.jpg',  'image/jpeg'],
  ['.jpeg', 'image/jpeg'],
  ['.gif',  'image/gif'],
  ['.webp', 'image/webp'],
  ['.svg',  'image/svg+xml'],
  ['.ico',  'image/x-icon'],
  ['.woff', 'font/woff'],
  ['.woff2','font/woff2'],
  ['.ttf',  'font/ttf'],
  ['.css',  'text/css'],
  ['.js',   'text/javascript'],
]);

const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
};

// ─── FLAT-FILE DATABASE ──────────────────────────────────────────────────────

const EMPTY_DB = { users: [], content: [], nextId: 1 };

function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify(EMPTY_DB, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// ─── PASSWORD HASHING (PBKDF2-SHA512) ───────────────────────────────────────

function hashPassword(password) {
  const salt = crypto.randomBytes(SALT_BYTES).toString('hex');
  const hash = crypto
    .pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_BYTES, 'sha512')
    .toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const attempt = crypto
    .pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_BYTES, 'sha512')
    .toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(attempt, 'hex'));
}

// ─── JWT (HMAC-SHA256) ───────────────────────────────────────────────────────

/** Encode a UTF-8 string as Base64URL without padding. */
function toBase64URL(str) {
  return Buffer.from(str).toString('base64url');
}

function makeJWT(payload) {
  const now    = Math.floor(Date.now() / 1000);
  const header = toBase64URL(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body   = toBase64URL(JSON.stringify({ ...payload, iat: now, exp: now + JWT_TTL_SECONDS }));
  const sig    = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyJWT(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp <= Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

// ─── HTTP HELPERS ────────────────────────────────────────────────────────────

function sendJSON(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type':   'application/json',
    'Content-Length': Buffer.byteLength(body),
    ...CORS_HEADERS,
  });
  res.end(body);
}

/**
 * Read and parse the request body as JSON.
 * Rejects if the body exceeds MAX_BODY_BYTES or is not valid JSON.
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    let bytes = 0;

    req.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > MAX_BODY_BYTES) {
        req.destroy();
        return reject(new Error('Payload too large'));
      }
      raw += chunk;
    });

    req.on('end', () => {
      try {
        resolve(JSON.parse(raw || '{}'));
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', reject);
  });
}

/** Strip the password hash before sending user data to a client. */
function sanitizeUser(user) {
  // eslint-disable-next-line no-unused-vars
  const { password_hash, ...safe } = user;
  return safe;
}

/** Extract and verify the Bearer token from the Authorization header. */
function extractAuthPayload(req) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  return token ? verifyJWT(token) : null;
}

// ─── IN-MEMORY ASSET CACHE ───────────────────────────────────────────────────

/** Cache for the main HTML file — loaded once, served on every GET request. */
let htmlCache = null;

function getHTML() {
  if (!htmlCache && fs.existsSync(HTML_FILE)) {
    htmlCache = fs.readFileSync(HTML_FILE);
  }
  return htmlCache;
}

// ─── ROUTE HANDLERS ─────────────────────────────────────────────────────────

async function handleRegister(req, res) {
  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return sendJSON(res, 400, { error: err.message });
  }

  const { first_name, last_name, email, password, role = 'viewer' } = body;

  if (!first_name || !last_name || !email || !password)
    return sendJSON(res, 400, { error: 'All fields are required' });
  if (!EMAIL_RE.test(email))
    return sendJSON(res, 400, { error: 'Invalid email format' });
  if (password.length < 6)
    return sendJSON(res, 400, { error: 'Password must be at least 6 characters' });
  if (!VALID_ROLES.has(role))
    return sendJSON(res, 400, { error: `Role must be one of: ${[...VALID_ROLES].join(', ')}` });

  const db = readDB();
  const normalizedEmail = email.trim().toLowerCase();
  const exists = db.users.find(u => u.email === normalizedEmail);
  if (exists) return sendJSON(res, 409, { error: 'Email already registered' });

  const user = {
    id:            db.nextId++,
    first_name:    first_name.trim(),
    last_name:     last_name.trim(),
    email:         normalizedEmail,
    password_hash: hashPassword(password),
    role,
    avatar_url:    null,
    created_at:    new Date().toISOString(),
  };

  db.users.push(user);
  writeDB(db);

  const token = makeJWT({ id: user.id, email: user.email, role: user.role });
  return sendJSON(res, 201, { token, user: sanitizeUser(user) });
}

async function handleLogin(req, res) {
  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return sendJSON(res, 400, { error: err.message });
  }

  const { email, password } = body;
  if (!email || !password)
    return sendJSON(res, 400, { error: 'Email and password required' });

  const db   = readDB();
  const user = db.users.find(u => u.email === email.trim().toLowerCase());

  // Deliberate same-message response to prevent user enumeration
  if (!user || !verifyPassword(password, user.password_hash))
    return sendJSON(res, 401, { error: 'Invalid email or password' });

  const token = makeJWT({ id: user.id, email: user.email, role: user.role });
  return sendJSON(res, 200, { token, user: sanitizeUser(user) });
}

function handleMe(req, res) {
  const payload = extractAuthPayload(req);
  if (!payload) return sendJSON(res, 401, { error: 'Invalid or expired token' });

  const db   = readDB();
  const user = db.users.find(u => u.id === payload.id);
  if (!user) return sendJSON(res, 404, { error: 'User not found' });

  return sendJSON(res, 200, { user: sanitizeUser(user) });
}

function handleGetContent(req, res) {
  const db = readDB();
  // Strip the deleteToken before sending to clients
  const content = (db.content || []).map(({ deleteToken: _dt, ...rest }) => rest);
  return sendJSON(res, 200, { content });
}

async function handlePostContent(req, res) {
  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return sendJSON(res, 400, { error: err.message });
  }

  const { title, desc, cat, catLabel, crew, cast, tags, video_url, uploaderId, uploaderHandle } = body;
  if (!title)     return sendJSON(res, 400, { error: 'title is required' });
  if (!video_url) return sendJSON(res, 400, { error: 'video_url is required' });

  const db = readDB();
  if (!db.content) db.content = [];

  const now         = Date.now();
  const deleteToken = crypto.randomBytes(SALT_BYTES).toString('hex');

  const item = {
    id:             now,
    title,
    desc:           desc           || '',
    cat:            cat            || 'ct-film',
    catLabel:       catLabel       || 'Фильм',
    crew:           crew           || [],
    cast:           cast           || [],
    tags:           tags           || [],
    video_url,
    uploaderId:     uploaderId     || null,
    uploaderHandle: uploaderHandle || null,
    deleteToken,
    ts:             now,
  };

  db.content.unshift(item);
  writeDB(db);

  return sendJSON(res, 201, { content: item, deleteToken });
}

async function handleDeleteContent(req, res, id) {
  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return sendJSON(res, 400, { error: err.message });
  }

  const { deleteToken } = body;
  if (!deleteToken) return sendJSON(res, 400, { error: 'deleteToken is required' });

  const db = readDB();
  const content = db.content || [];
  const idx = content.findIndex(c => c.id === id);
  if (idx === -1) return sendJSON(res, 404, { error: 'Content not found' });

  if (content[idx].deleteToken !== deleteToken)
    return sendJSON(res, 403, { error: 'Not authorized' });

  content.splice(idx, 1);
  writeDB(db);

  return sendJSON(res, 200, { success: true });
}

// ─── BUNNY UPLOAD HANDLERS ──────────────────────────────────────────────────

const BUNNY_LIBRARY_ID  = process.env.BUNNY_STREAM_LIBRARY_ID;
const BUNNY_STREAM_KEY  = process.env.BUNNY_STREAM_API_KEY;
const BUNNY_STORAGE_ZONE = process.env.BUNNY_STORAGE_ZONE;
const BUNNY_STORAGE_KEY  = process.env.BUNNY_STORAGE_API_KEY;
const BUNNY_STORAGE_HOST = process.env.BUNNY_STORAGE_REGION || 'storage.bunnycdn.com';
const BUNNY_CDN_HOST     = process.env.BUNNY_CDN_HOSTNAME;

const UPLOAD_MAX_BYTES = 200 * 1024 * 1024; // 200 MB for video; Vercel has 4.5 MB limit on serverless

function bunnyTusUrl(location) {
  const value = String(location || '').trim();
  if (!value) return '';
  if (value.startsWith('https://video.bunnycdn.com/')) return value;
  if (value.startsWith('/')) return `https://video.bunnycdn.com${value}`;
  if (value.startsWith('tusupload/')) return `https://video.bunnycdn.com/${value}`;
  return value;
}

function bunnyTusAuthHeaders(videoId, expireTime) {
  const signature = crypto
    .createHash('sha256')
    .update(String(BUNNY_LIBRARY_ID) + BUNNY_STREAM_KEY + String(expireTime) + String(videoId))
    .digest('hex');

  return {
    'AuthorizationSignature': signature,
    'AuthorizationExpire':    String(expireTime),
    'LibraryId':              String(BUNNY_LIBRARY_ID),
    'VideoId':                String(videoId),
  };
}

/**
 * Buffer the entire request body (up to maxBytes).
 * Returns a Buffer; throws if limit exceeded.
 */
function readRawBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', chunk => {
      total += chunk.length;
      if (total > maxBytes) { req.destroy(); return reject(new Error('Payload too large')); }
      chunks.push(chunk);
    });
    req.on('end',   () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/**
 * Parse a multipart/form-data buffer.
 * Returns the file binary and its MIME type for the first file field found.
 */
function parseMultipartFile(body, boundary) {
  const boundaryBuf = Buffer.from('--' + boundary);
  const CRLF        = Buffer.from('\r\n');
  const doubleCRLF  = Buffer.from('\r\n\r\n');

  let pos = body.indexOf(boundaryBuf);
  if (pos === -1) return null;
  pos += boundaryBuf.length + 2; // skip past boundary + CRLF

  // Find headers
  const headersEnd = body.indexOf(doubleCRLF, pos);
  if (headersEnd === -1) return null;

  const headerBlock = body.slice(pos, headersEnd).toString('utf8');
  const mimeMatch   = headerBlock.match(/Content-Type:\s*([^\r\n]+)/i);
  const nameMatch   = headerBlock.match(/filename="([^"]+)"/i);
  const mimeType    = mimeMatch ? mimeMatch[1].trim() : 'application/octet-stream';
  const filename    = nameMatch ? nameMatch[1] : 'upload';

  // File data starts after double CRLF
  const dataStart = headersEnd + 4;

  // File data ends before the next boundary (which starts with \r\n--)
  const endMarker    = Buffer.from('\r\n--' + boundary);
  const dataEnd      = body.indexOf(endMarker, dataStart);
  if (dataEnd === -1) return null;

  return { data: body.slice(dataStart, dataEnd), mimeType, filename };
}

/**
 * Make an HTTPS request, returns { status, body }
 */
function httpsRequest(url, options, bodyBuffer) {
  return new Promise((resolve, reject) => {
    const https = require('https');
    const req = https.request(url, options, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        body: Buffer.concat(chunks).toString(),
        headers: res.headers,
      }));
    });
    req.on('error', reject);
    if (bodyBuffer) req.write(bodyBuffer);
    req.end();
  });
}

async function handleUploadVideo(req, res) {
  if (!BUNNY_LIBRARY_ID || !BUNNY_STREAM_KEY) {
    return sendJSON(res, 503, { error: 'Bunny Stream not configured. Set BUNNY_STREAM_LIBRARY_ID and BUNNY_STREAM_API_KEY.' });
  }

  const ct = req.headers['content-type'] || '';
  const boundaryMatch = ct.match(/boundary=([^\s;]+)/);
  if (!boundaryMatch) return sendJSON(res, 400, { error: 'Missing multipart boundary.' });

  let body;
  try {
    body = await readRawBody(req, UPLOAD_MAX_BYTES);
  } catch (e) {
    return sendJSON(res, 413, { error: e.message });
  }

  const parsed = parseMultipartFile(body, boundaryMatch[1]);
  if (!parsed) return sendJSON(res, 400, { error: 'Could not parse file from multipart body.' });

  // Step 1: Create a Bunny Stream video record → get guid
  const createRes = await httpsRequest(
    `https://video.bunnycdn.com/library/${BUNNY_LIBRARY_ID}/videos`,
    {
      method: 'POST',
      headers: {
        'AccessKey': BUNNY_STREAM_KEY,
        'Content-Type': 'application/json',
      },
    },
    Buffer.from(JSON.stringify({ title: parsed.filename }))
  );

  if (createRes.status < 200 || createRes.status >= 300) {
    return sendJSON(res, 502, { error: `Bunny Stream create failed (${createRes.status}): ${createRes.body}` });
  }

  let guid;
  try {
    guid = JSON.parse(createRes.body).guid;
  } catch {
    return sendJSON(res, 502, { error: 'Unexpected Bunny response: ' + createRes.body });
  }

  // Step 2: Upload the video binary to Bunny Stream
  const uploadRes = await httpsRequest(
    `https://video.bunnycdn.com/library/${BUNNY_LIBRARY_ID}/videos/${guid}`,
    {
      method: 'PUT',
      headers: {
        'AccessKey': BUNNY_STREAM_KEY,
        'Content-Type': 'application/octet-stream',
        'Content-Length': parsed.data.length,
      },
    },
    parsed.data
  );

  if (uploadRes.status < 200 || uploadRes.status >= 300) {
    return sendJSON(res, 502, { error: `Bunny Stream upload failed (${uploadRes.status}): ${uploadRes.body}` });
  }

  return sendJSON(res, 200, {
    bunny_video_id:    guid,
    bunny_library_id:  BUNNY_LIBRARY_ID,
    video_embed_url:   `https://iframe.mediadelivery.net/embed/${BUNNY_LIBRARY_ID}/${guid}`,
    video_playback_url:`https://iframe.mediadelivery.net/play/${BUNNY_LIBRARY_ID}/${guid}`,
    duration:          null, // Bunny encodes asynchronously; poll /videos/{guid} if needed
  });
}

async function handleUploadImage(req, res) {
  if (!BUNNY_STORAGE_ZONE || !BUNNY_STORAGE_KEY || !BUNNY_CDN_HOST) {
    return sendJSON(res, 503, { error: 'Bunny Storage not configured. Set BUNNY_STORAGE_ZONE, BUNNY_STORAGE_API_KEY, and BUNNY_CDN_HOSTNAME.' });
  }

  const ct = req.headers['content-type'] || '';
  const boundaryMatch = ct.match(/boundary=([^\s;]+)/);
  if (!boundaryMatch) return sendJSON(res, 400, { error: 'Missing multipart boundary.' });

  let body;
  try {
    body = await readRawBody(req, 10 * 1024 * 1024); // 10 MB limit for images
  } catch (e) {
    return sendJSON(res, 413, { error: e.message });
  }

  const parsed = parseMultipartFile(body, boundaryMatch[1]);
  if (!parsed) return sendJSON(res, 400, { error: 'Could not parse file from multipart body.' });

  const ext      = (parsed.filename.match(/\.[^.]+$/) || ['.jpg'])[0];
  const fileName = `thumbnails/${Date.now()}-${Math.random().toString(36).slice(2, 8)}${ext}`;

  const uploadRes = await httpsRequest(
    `https://${BUNNY_STORAGE_HOST}/${BUNNY_STORAGE_ZONE}/${fileName}`,
    {
      method: 'PUT',
      headers: {
        'AccessKey': BUNNY_STORAGE_KEY,
        'Content-Type': parsed.mimeType,
        'Content-Length': parsed.data.length,
      },
    },
    parsed.data
  );

  if (uploadRes.status < 200 || uploadRes.status >= 300) {
    return sendJSON(res, 502, { error: `Bunny Storage upload failed (${uploadRes.status}): ${uploadRes.body}` });
  }

  return sendJSON(res, 200, {
    thumbnail_url: `https://${BUNNY_CDN_HOST}/${fileName}`,
  });
}

/**
 * Phase 1 of the chunked video upload flow.
 * Creates a Bunny Stream video record and a TUS resumable-upload session.
 * Returns the session location URL so the client can proxy chunks through
 * /api/upload-chunk without ever seeing the Bunny API key.
 *
 * Body: { title: string, size: number }
 */
async function handleCreateVideo(req, res) {
  if (!BUNNY_LIBRARY_ID || !BUNNY_STREAM_KEY) {
    return sendJSON(res, 503, { error: 'Bunny Stream not configured. Set BUNNY_STREAM_LIBRARY_ID and BUNNY_STREAM_API_KEY.' });
  }

  let title = 'upload';
  let totalSize = 0;
  try {
    const body = await readRawBody(req, 8192);
    const parsed = JSON.parse(body.toString());
    title    = String(parsed.title || 'upload');
    totalSize = parseInt(parsed.size) || 0;
  } catch { /* use defaults */ }

  // Step 1: Create Bunny video record → get guid
  const createRes = await httpsRequest(
    `https://video.bunnycdn.com/library/${BUNNY_LIBRARY_ID}/videos`,
    {
      method: 'POST',
      headers: { 'AccessKey': BUNNY_STREAM_KEY, 'Content-Type': 'application/json' },
    },
    Buffer.from(JSON.stringify({ title }))
  );

  if (createRes.status < 200 || createRes.status >= 300) {
    return sendJSON(res, 502, { error: `Bunny Stream create failed (${createRes.status}): ${createRes.body}` });
  }

  let guid;
  try { guid = JSON.parse(createRes.body).guid; }
  catch { return sendJSON(res, 502, { error: 'Unexpected Bunny response: ' + createRes.body }); }

  // Step 2: Create TUS resumable-upload session
  const expireTime   = Math.floor(Date.now() / 1000) + 7200; // 2-hour window
  const b64          = s => Buffer.from(String(s)).toString('base64');
  const uploadMeta   = `filetype ${b64('video/mp4')},title ${b64(title)}`;
  const authHeaders  = bunnyTusAuthHeaders(guid, expireTime);

  const tusRes = await httpsRequest(
    'https://video.bunnycdn.com/tusupload',
    {
      method: 'POST',
      headers: {
        ...authHeaders,
        'Tus-Resumable':          '1.0.0',
        'Upload-Length':          String(totalSize),
        'Upload-Metadata':        uploadMeta,
      },
    }
  );

  if (tusRes.status !== 201) {
    return sendJSON(res, 502, { error: `Bunny TUS session failed (${tusRes.status}): ${tusRes.body}` });
  }

  const tusLocation = bunnyTusUrl(tusRes.headers && tusRes.headers['location']);
  if (!tusLocation) {
    return sendJSON(res, 502, { error: 'Bunny TUS did not return a Location header.' });
  }

  return sendJSON(res, 200, {
    guid,
    library_id:   BUNNY_LIBRARY_ID,
    tus_location: tusLocation,
    tus_expire:   expireTime,
    embed_url:    `https://iframe.mediadelivery.net/embed/${BUNNY_LIBRARY_ID}/${guid}`,
    playback_url: `https://iframe.mediadelivery.net/play/${BUNNY_LIBRARY_ID}/${guid}`,
  });
}

/**
 * Phase 2 of the chunked video upload flow.
 * Receives one chunk (≤ 4 MB) from the browser and PATCHes it to the
 * Bunny TUS location.  Query params:
 *   tus_url  – URL-encoded Bunny TUS location
 *   offset   – byte offset of this chunk
 *   total    – total file size in bytes
 */
async function handleUploadChunk(req, res) {
  const rawUrl  = req.url || '';
  const qs      = rawUrl.includes('?') ? rawUrl.slice(rawUrl.indexOf('?') + 1) : '';
  const params  = new URLSearchParams(qs);
  const tusUrl  = bunnyTusUrl(params.get('tus_url'));
  const videoId = params.get('video_id') || params.get('videoId');
  const offset  = parseInt(params.get('offset') || '0');
  const total   = parseInt(params.get('total')  || '0');

  if (!tusUrl) return sendJSON(res, 400, { error: 'Missing tus_url parameter.' });
  if (!videoId) return sendJSON(res, 400, { error: 'Missing video_id parameter.' });

  // Safety: only allow proxying to Bunny's own domain
  if (!tusUrl.startsWith('https://video.bunnycdn.com/')) {
    return sendJSON(res, 400, { error: 'Invalid TUS location domain.' });
  }

  let chunk;
  try {
    chunk = await readRawBody(req, UPLOAD_MAX_BYTES);
  } catch (e) {
    return sendJSON(res, 413, { error: e.message });
  }

  const expireTime = Math.floor(Date.now() / 1000) + 7200;
  const patchRes = await httpsRequest(
    tusUrl,
    {
      method: 'PATCH',
      headers: {
        ...bunnyTusAuthHeaders(videoId, expireTime),
        'Content-Type':   'application/offset+octet-stream',
        'Content-Length': String(chunk.length),
        'Upload-Offset':  String(offset),
        'Tus-Resumable':  '1.0.0',
      },
    },
    chunk
  );

  // TUS spec: 204 No Content on success; some servers return 200
  if (patchRes.status !== 204 && patchRes.status !== 200) {
    return sendJSON(res, 502, { error: `Bunny TUS patch failed (${patchRes.status}): ${patchRes.body}` });
  }

  const uploaded = offset + chunk.length;
  return sendJSON(res, 200, {
    uploaded,
    total,
    complete: uploaded >= total,
  });
}

function handleAsset(req, res, assetPath) {
  if (!fs.existsSync(assetPath)) {
    res.writeHead(404);
    return res.end('Asset not found');
  }

  const ext         = path.extname(assetPath).toLowerCase();
  const contentType = MIME_TYPES.get(ext) || 'application/octet-stream';
  const data        = fs.readFileSync(assetPath);

  res.writeHead(200, {
    'Content-Type':  contentType,
    'Content-Length': data.length,
    'Cache-Control': 'public, max-age=31536000, immutable',
  });
  return res.end(data);
}

function handleHTML(req, res) {
  const html = getHTML();
  if (!html) {
    res.writeHead(404);
    return res.end('Not found');
  }
  res.writeHead(200, {
    'Content-Type':  'text/html; charset=utf-8',
    'Content-Length': html.length,
  });
  return res.end(html);
}

// ─── ROUTER ──────────────────────────────────────────────────────────────────

const DELETE_CONTENT_RE = /^\/api\/content\/(\d+)$/;

async function router(req, res) {
  const url    = req.url.split('?')[0];
  const method = req.method.toUpperCase();

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS);
    return res.end();
  }

  if (method === 'POST'   && url === '/api/register') return handleRegister(req, res);
  if (method === 'POST'   && url === '/api/login')    return handleLogin(req, res);
  if (method === 'GET'    && url === '/api/me')        return handleMe(req, res);
  if (method === 'POST'   && url === '/api/upload-video')  return handleUploadVideo(req, res);
  if (method === 'POST'   && url === '/api/upload-image')  return handleUploadImage(req, res);
  if (method === 'POST'   && url === '/api/create-video')  return handleCreateVideo(req, res);
  if (method === 'POST'   && url === '/api/upload-chunk')  return handleUploadChunk(req, res);
  if (method === 'GET'    && url === '/api/content')   return handleGetContent(req, res);
  if (method === 'POST'   && url === '/api/content')   return handlePostContent(req, res);

  const deleteMatch = method === 'DELETE' && DELETE_CONTENT_RE.exec(url);
  if (deleteMatch) return handleDeleteContent(req, res, parseInt(deleteMatch[1], 10));

  if (method === 'GET' && url.startsWith('/assets/')) {
    const assetPath = path.join(__dirname, url);
    return handleAsset(req, res, assetPath);
  }

  if (method === 'GET') return handleHTML(req, res);

  return sendJSON(res, 404, { error: 'Not found' });
}

// ─── START ───────────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  try {
    await router(req, res);
  } catch (err) {
    console.error('[server] Unhandled error:', err);
    sendJSON(res, 500, { error: 'Internal server error' });
  }
});

server.listen(PORT, () => {
  console.log('');
  console.log('  🎬 Kórseteıik server ready');
  console.log(`  → http://localhost:${PORT}`);
  console.log(`  → Database: ${DB_FILE}`);
  console.log('');
});
