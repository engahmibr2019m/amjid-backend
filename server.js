'use strict';
/**
 * خادم موقع أمجد + حساب أدمن واحد (بدون أي مكتبات خارجية)
 *
 * التشغيل:
 *   node server.js
 *   ثم افتح:  http://localhost:8080/
 *
 * عند أول تشغيل يُنشأ حساب admin بكلمة مرور عشوائية وتظهر في نافذة الخادم مرة واحدة.
 * يُحفظ تجزؤ كلمة المرور في .admin-account.json. لحساب جديد، احذف الملف وأعد التشغيل.
 *
 * endpoints:
 *   POST /api/login   {username,password} → كوكي جلسة HttpOnly
 *   POST /api/logout  يغلق الجلسة
 *   GET  /api/me      {authenticated,username}
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '8080', 10);
const ACCOUNT_FILE = path.join(__dirname, '.admin-account.json');
const HOME_PAGE = 'amgad (2).html';           // الصفحة الوحيدة
const SESSION_COOKIE = 'amgad_session';
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;  // 7 أيام
const MAX_BODY = 16 * 1024;                  // أقصى حجم لطلب (الدخول أو إضافة كارت)
const RATE_LIMIT = 5;                         // محاولات خاطئة قبل التجميد
const RATE_WINDOW = 15 * 60 * 1000;           // 15 دقيقة

const ROOT = __dirname;
const sessions = new Map();                   // توكن -> { user, expires }
const attempts = new Map();                   // ip -> { n, until }

function loadAdminAccount() {
  try {
    const account = JSON.parse(fs.readFileSync(ACCOUNT_FILE, 'utf8'));
    if (account.username === 'admin' && /^[a-f0-9]{32}$/.test(account.salt) && /^[a-f0-9]{128}$/.test(account.hash)) return account;
    throw new Error('invalid account file');
  } catch (err) {
    if (err.code !== 'ENOENT') throw new Error('ملف حساب الأدمن غير صالح: ' + ACCOUNT_FILE);
    const password = crypto.randomBytes(18).toString('base64url');
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    const account = { username: 'admin', salt, hash };
    fs.writeFileSync(ACCOUNT_FILE, JSON.stringify(account, null, 2), { encoding: 'utf8', flag: 'wx' });
    console.log('\n  تم إنشاء حساب الأدمن الوحيد:');
    console.log('  اسم المستخدم: admin');
    console.log('  كلمة المرور (احفظها الآن): ' + password + '\n');
    return account;
  }
}
const ADMIN_ACCOUNT = loadAdminAccount();

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
  '.webp': 'image/webp', '.gif': 'image/gif', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.mp4': 'video/mp4', '.webm': 'video/webm'
};

function send(res, code, body, headers) {
  res.writeHead(code, headers || {});
  res.end(body);
}

function json(res, code, obj, extra) {
  const body = JSON.stringify(obj);
  send(res, code, body, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  }, extra || {}));
}

/* مقارنة آمنة زمنياً (نقارن الـ hash عشان الطول مختلف) */
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i < 0) return;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function rateAllowed(ip) {
  const now = Date.now();
  const a = attempts.get(ip);
  if (!a) return true;
  if (now > a.until) { attempts.delete(ip); return true; }
  return a.n < RATE_LIMIT;
}
function rateHit(ip) {
  const now = Date.now();
  const a = attempts.get(ip);
  if (!a || now > a.until) attempts.set(ip, { n: 1, until: now + RATE_WINDOW });
  else a.n += 1;
}
function rateReset(ip) { attempts.delete(ip); }

function currentSession(req) {
  const token = parseCookies(req)[SESSION_COOKIE];
  const s = token && sessions.get(token);
  if (!s) return null;
  if (s.expires < Date.now()) { sessions.delete(token); return null; }
  return { token, user: s.user };
}

function pruneSessions() {
  const now = Date.now();
  sessions.forEach((s, t) => { if (s.expires < now) sessions.delete(t); });
}

/* ---------- كروت الفيديو المضافة ---------- */
const CARDS_FILE = path.join(ROOT, 'cards.json');

function readCards() {
  try {
    const arr = JSON.parse(fs.readFileSync(CARDS_FILE, 'utf8'));
    return Array.isArray(arr) ? arr : [];
  } catch (e) {
    return [];                    // أول مرة: ملف لسه مش موجود
  }
}
function writeCards(cards) {
  fs.writeFileSync(CARDS_FILE, JSON.stringify(cards, null, 2), 'utf8');
}
function isValidUrl(u) {
  return typeof u === 'string' && u.length <= 2048 && /^https?:\/\/\S+$/i.test(u);
}
async function handleAddCard(req, res) {
  if (!currentSession(req)) return json(res, 401, { ok: false, error: 'unauthorized' });
  let data;
  try {
    data = JSON.parse(await readBody(req));
  } catch (e) {
    return json(res, 400, { ok: false, error: 'bad_request' });
  }
  const n = Number(data.n);
  const img = typeof data.img === 'string' ? data.img.trim() : '';
  const video = typeof data.video === 'string' ? data.video.trim() : '';
  if (!Number.isInteger(n) || n < 1 || n > 9999 || !isValidUrl(img) || !isValidUrl(video)) {
    return json(res, 400, { ok: false, error: 'invalid' });
  }
  const cards = readCards().filter(c => c.n !== n);      // نفس الرقم = استبدال
  cards.push({ n: n, img: img, video: video, addedAt: new Date().toISOString() });
  cards.sort((a, b) => a.n - b.n);
  try {
    writeCards(cards);
  } catch (e) {
    return json(res, 500, { ok: false, error: 'write_failed' });
  }
  return json(res, 200, { ok: true, cards: cards });
}

/* ---------- API ---------- */
async function handleLogin(req, res) {
  const ip = req.socket.remoteAddress || 'unknown';
  if (!rateAllowed(ip)) {
    return json(res, 429, { ok: false, error: 'too_many' });
  }
  let data;
  try {
    data = JSON.parse(await readBody(req));
  } catch (e) {
    return json(res, 400, { ok: false, error: 'bad_request' });
  }
  const username = typeof data.username === 'string' ? data.username : '';
  const password = typeof data.password === 'string' ? data.password : '';
  const okUser = safeEqual(username, ADMIN_ACCOUNT.username);
  const candidate = crypto.scryptSync(password, ADMIN_ACCOUNT.salt, 64);
  const expected = Buffer.from(ADMIN_ACCOUNT.hash, 'hex');
  const okPass = crypto.timingSafeEqual(candidate, expected);
  const ok = okUser & okPass;               // و bitwise عشان يقارن الاتنين دائماً
  if (!ok) {
    rateHit(ip);
    return json(res, 401, { ok: false, error: 'bad_credentials' });
  }
  rateReset(ip);
  pruneSessions();
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { user: ADMIN_ACCOUNT.username, expires: Date.now() + SESSION_TTL });
  return json(res, 200, { ok: true, username: ADMIN_ACCOUNT.username }, {
    'Set-Cookie': SESSION_COOKIE + '=' + token +
      '; HttpOnly; Path=/; SameSite=Lax; Max-Age=' + Math.floor(SESSION_TTL / 1000)
  });
}

function handleLogout(req, res) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (token) sessions.delete(token);
  return json(res, 200, { ok: true }, {
    'Set-Cookie': SESSION_COOKIE + '=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0'
  });
}

function handleMe(req, res) {
  const s = currentSession(req);
  return json(res, 200, { authenticated: !!s, username: s ? s.user : null });
}

/* ---------- الملفات الثابتة ---------- */
function serveStatic(req, res) {
  let urlPath;
  try {
    urlPath = decodeURIComponent(req.url.split('?')[0]);
  } catch (e) {
    return send(res, 400, 'Bad Request');
  }
  // ملفات الخادم والبيانات الداخلية لا تُعرض كملفات عامة.
  if (urlPath.split('/').some(part => part.startsWith('.')) ||
      ['/server.js', '/start-server.bat', '/cards.json'].includes(urlPath.toLowerCase())) {
    return send(res, 404, 'Not Found');
  }
  if (urlPath === '/' ) urlPath = '/' + HOME_PAGE;

  const filePath = path.normalize(path.join(ROOT, urlPath));
  if (filePath !== ROOT && !filePath.startsWith(ROOT + path.sep)) {
    return send(res, 403, 'Forbidden');
  }

  fs.stat(filePath, (err, st) => {
    if (err || !st.isFile()) return send(res, 404, 'Not Found');
    const type = MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
    const base = {
      'Content-Type': type,
      'Accept-Ranges': 'bytes',
      'X-Content-Type-Options': 'nosniff'
    };

    /* دعم Range عشان مشغّل الفيديو */
    const range = req.headers.range;
    if (range && /^bytes=\d*-\d*$/.test(range)) {
      const m = range.replace('bytes=', '').split('-');
      let start = m[0] ? parseInt(m[0], 10) : 0;
      let end = m[1] ? parseInt(m[1], 10) : st.size - 1;
      if (isNaN(start) || start >= st.size) start = 0;
      if (isNaN(end) || end >= st.size) end = st.size - 1;
      if (start > end) return send(res, 416, '', { 'Content-Range': 'bytes */' + st.size });
      res.writeHead(206, Object.assign({}, base, {
        'Content-Range': 'bytes ' + start + '-' + end + '/' + st.size,
        'Content-Length': end - start + 1
      }));
      if (req.method === 'HEAD') return res.end();
      const stream = fs.createReadStream(filePath, { start, end });
      stream.on('error', () => res.destroy());
      return stream.pipe(res);
    }

    res.writeHead(200, Object.assign({}, base, { 'Content-Length': st.size }));
    if (req.method === 'HEAD') return res.end();
    const stream = fs.createReadStream(filePath);
    stream.on('error', () => res.destroy());
    stream.pipe(res);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = req.url.split('?')[0];
    if (url === '/api/login' && req.method === 'POST') return await handleLogin(req, res);
    if (url === '/api/logout' && req.method === 'POST') return handleLogout(req, res);
    if (url === '/api/me' && req.method === 'GET') return handleMe(req, res);
    if (url === '/api/cards' && req.method === 'GET') return json(res, 200, { ok: true, cards: readCards() });
    if (url === '/api/cards' && req.method === 'POST') return await handleAddCard(req, res);
    if (url.indexOf('/api/') === 0) return json(res, 404, { ok: false, error: 'not_found' });
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return send(res, 405, 'Method Not Allowed');
    }
    return serveStatic(req, res);
  } catch (e) {
    return json(res, 500, { ok: false, error: 'server_error' });
  }
});

server.listen(PORT, () => {
  console.log('✔ خادم أمجد شغّال على  http://localhost:' + PORT + '/');
  console.log('  اسم حساب الأدمن: admin');
});
