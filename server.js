// ULTRA Message — общий сервер
// ------------------------------------------------------------
// Ни одной внешней зависимости: только встроенные модули Node.js.
// Хранилище — один JSON-файл (db.json) рядом со скриптом.
// Для реальной нагрузки этого недостаточно, но для личного/демо-проекта — самое то:
// разворачивается на любом хостинге, где есть Node.js, командой `node server.js`.
// ------------------------------------------------------------

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');

// ---------- ХРАНИЛИЩЕ ----------
function loadDb(){
  if (!fs.existsSync(DB_FILE)) {
    return { users: [], sessions: [], messages: [], nextUserId: 1, nextMessageId: 1 };
  }
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (err) {
    console.error('Не удалось прочитать db.json, начинаю с чистой базы:', err.message);
    return { users: [], sessions: [], messages: [], nextUserId: 1, nextMessageId: 1 };
  }
}

let db = loadDb();
let saveScheduled = false;
function saveDb(){
  // Небольшая отложенная запись, чтобы много быстрых изменений подряд не долбили диск —
  // но не позже чем через один тик события, так что данные почти всегда на диске сразу.
  if (saveScheduled) return;
  saveScheduled = true;
  setImmediate(() => {
    saveScheduled = false;
    fs.writeFileSync(DB_FILE, JSON.stringify(db), 'utf8');
  });
}

// ---------- ПАРОЛИ И ТОКЕНЫ ----------
function hashPassword(password, salt){
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, hash){
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(check, 'hex'), Buffer.from(hash, 'hex'));
}
function newToken(){
  return crypto.randomBytes(32).toString('hex');
}

// ---------- ВСПОМОГАТЕЛЬНОЕ ----------
function normalizeUsername(u){
  return (u || '').trim().replace(/^@/, '').toLowerCase();
}
function digitsOnly(s){
  return (s || '').replace(/\D/g, '');
}
function publicUser(u){
  // То, что можно безопасно показать другим пользователям (без пароля/соли)
  return {
    id: u.id, name: u.name, username: u.username,
    phone: u.phonePrivate ? null : u.phone,
    phonePrivate: !!u.phonePrivate,
    bio: u.bio || '', colorIndex: u.colorIndex || 0, avatarPhoto: u.avatarPhoto || null
  };
}
function meUser(u){
  // Полная версия для самого владельца аккаунта (телефон всегда виден себе)
  return {
    id: u.id, name: u.name, username: u.username, phone: u.phone,
    phonePrivate: !!u.phonePrivate, bio: u.bio || '',
    colorIndex: u.colorIndex || 0, avatarPhoto: u.avatarPhoto || null
  };
}
function conversationKey(idA, idB){
  return [idA, idB].sort((a, b) => a - b).join('-');
}

function findUserByToken(token){
  if (!token) return null;
  const session = db.sessions.find(s => s.token === token);
  if (!session) return null;
  return db.users.find(u => u.id === session.userId) || null;
}

// ---------- HTTP-ОТВЕТЫ ----------
function send(res, status, body){
  const json = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(json),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
  });
  res.end(json);
}
function readBody(req){
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > 8 * 1024 * 1024) { reject(new Error('payload_too_large')); req.destroy(); return; }
      data += chunk;
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); }
      catch (err) { reject(new Error('invalid_json')); }
    });
    req.on('error', reject);
  });
}
function getToken(req, query){
  const header = req.headers['authorization'] || '';
  const match = header.match(/^Bearer (.+)$/);
  if (match) return match[1];
  if (query) { const qp = query.get('token'); if (qp) return qp; }
  return null;
}

// ---------- МАРШРУТЫ ----------
const routes = [];
function route(method, pattern, handler){
  // pattern вида '/api/dm/:id' -> регулярка с именованными группами
  const paramNames = [];
  const regexStr = pattern.replace(/:[a-zA-Z]+/g, (m) => {
    paramNames.push(m.slice(1));
    return '([^/]+)';
  });
  const regex = new RegExp('^' + regexStr + '$');
  routes.push({ method, regex, paramNames, handler });
}

route('GET', '/api/health', async (req, res) => {
  send(res, 200, { ok: true, users: db.users.length, uptime: process.uptime() });
});

route('POST', '/api/register', async (req, res) => {
  const body = await readBody(req);
  const name = (body.name || '').trim();
  const username = (body.username || '').trim();
  const phone = (body.phone || '').trim();
  const password = body.password || '';
  const colorIndex = Number.isInteger(body.colorIndex) ? body.colorIndex : 0;

  if (!name || !username || !phone || password.length < 6) {
    return send(res, 400, { error: 'invalid_input', message: 'Заполните имя, логин, телефон и пароль (минимум 6 символов)' });
  }
  const usernameKey = normalizeUsername(username);
  const phoneDigits = digitsOnly(phone);
  if (db.users.some(u => u.usernameKey === usernameKey)) {
    return send(res, 409, { error: 'username_taken', message: 'Этот логин уже занят' });
  }
  if (db.users.some(u => u.phoneDigits === phoneDigits)) {
    return send(res, 409, { error: 'phone_taken', message: 'Этот номер телефона уже зарегистрирован' });
  }

  const { salt, hash } = hashPassword(password);
  const user = {
    id: db.nextUserId++,
    usernameKey, username, phone, phoneDigits, phonePrivate: false,
    name, bio: '', colorIndex, avatarPhoto: null,
    passwordSalt: salt, passwordHash: hash,
    data: null, // персональный блок (контакты/переписки с ботом/группы/звонки/стикеры)
    createdAt: Date.now()
  };
  db.users.push(user);
  const token = newToken();
  db.sessions.push({ token, userId: user.id, createdAt: Date.now() });
  saveDb();
  send(res, 200, { token, user: meUser(user) });
});

route('POST', '/api/login', async (req, res) => {
  const body = await readBody(req);
  const usernameKey = normalizeUsername(body.username || '');
  const password = body.password || '';
  const user = db.users.find(u => u.usernameKey === usernameKey);
  if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
    return send(res, 401, { error: 'invalid_credentials', message: 'Неверный логин или пароль' });
  }
  const token = newToken();
  db.sessions.push({ token, userId: user.id, createdAt: Date.now() });
  saveDb();
  send(res, 200, { token, user: meUser(user) });
});

route('POST', '/api/logout', async (req, res) => {
  const token = getToken(req);
  db.sessions = db.sessions.filter(s => s.token !== token);
  saveDb();
  send(res, 200, { ok: true });
});

route('GET', '/api/me', async (req, res) => {
  const user = findUserByToken(getToken(req));
  if (!user) return send(res, 401, { error: 'unauthorized' });
  send(res, 200, { user: meUser(user), data: user.data });
});

route('PUT', '/api/me/profile', async (req, res) => {
  const user = findUserByToken(getToken(req));
  if (!user) return send(res, 401, { error: 'unauthorized' });
  const body = await readBody(req);
  if (typeof body.name === 'string' && body.name.trim()) user.name = body.name.trim();
  if (typeof body.username === 'string' && body.username.trim()) {
    const newKey = normalizeUsername(body.username);
    const taken = db.users.some(u => u.id !== user.id && u.usernameKey === newKey);
    if (taken) return send(res, 409, { error: 'username_taken', message: 'Этот логин уже занят' });
    user.username = body.username.trim();
    user.usernameKey = newKey;
  }
  if (typeof body.bio === 'string') user.bio = body.bio;
  if (Number.isInteger(body.colorIndex)) user.colorIndex = body.colorIndex;
  if (typeof body.avatarPhoto === 'string' || body.avatarPhoto === null) user.avatarPhoto = body.avatarPhoto;
  if (typeof body.phonePrivate === 'boolean') user.phonePrivate = body.phonePrivate;
  saveDb();
  send(res, 200, { user: meUser(user) });
});

route('PUT', '/api/me/data', async (req, res, query) => {
  const user = findUserByToken(getToken(req, query));
  if (!user) return send(res, 401, { error: 'unauthorized' });
  const body = await readBody(req);
  user.data = body.data || null;
  saveDb();
  send(res, 200, { ok: true });
});
// navigator.sendBeacon умеет отправлять только POST — отдельный маршрут для сохранения при закрытии вкладки
route('POST', '/api/me/data', async (req, res, query) => {
  const user = findUserByToken(getToken(req, query));
  if (!user) return send(res, 401, { error: 'unauthorized' });
  const body = await readBody(req);
  user.data = body.data || null;
  saveDb();
  send(res, 200, { ok: true });
});

route('GET', '/api/users/search', async (req, res, query) => {
  const user = findUserByToken(getToken(req));
  if (!user) return send(res, 401, { error: 'unauthorized' });
  const term = normalizeUsername(query.get('q') || '');
  if (!term) return send(res, 200, { users: [] });
  const termDigits = digitsOnly(term);
  const results = db.users
    .filter(u => u.id !== user.id)
    .filter(u => {
      const name = u.name.toLowerCase();
      const uname = u.username.toLowerCase();
      const phoneDigits = u.phoneDigits || '';
      return name.includes(term) || uname.includes(term) || (termDigits.length > 0 && phoneDigits.includes(termDigits));
    })
    .slice(0, 20)
    .map(publicUser);
  send(res, 200, { users: results });
});

route('GET', '/api/dm/:otherId', async (req, res, query, params) => {
  const user = findUserByToken(getToken(req));
  if (!user) return send(res, 401, { error: 'unauthorized' });
  const otherId = parseInt(params.otherId, 10);
  const other = db.users.find(u => u.id === otherId);
  if (!other) return send(res, 404, { error: 'not_found' });
  const key = conversationKey(user.id, otherId);
  const since = parseInt(query.get('since') || '0', 10);
  const messages = db.messages.filter(m => m.conversationKey === key && m.id > since);
  send(res, 200, { messages, otherUser: publicUser(other) });
});

route('POST', '/api/dm/:otherId', async (req, res, query, params) => {
  const user = findUserByToken(getToken(req));
  if (!user) return send(res, 401, { error: 'unauthorized' });
  const otherId = parseInt(params.otherId, 10);
  const other = db.users.find(u => u.id === otherId);
  if (!other) return send(res, 404, { error: 'not_found' });
  const body = await readBody(req);
  const text = (body.text || '').trim();
  if (!text) return send(res, 400, { error: 'empty_message' });
  const message = {
    id: db.nextMessageId++,
    conversationKey: conversationKey(user.id, otherId),
    senderId: user.id, recipientId: otherId,
    text, createdAt: Date.now()
  };
  db.messages.push(message);
  saveDb();
  send(res, 200, { message });
});

// ---------- СЕРВЕР ----------
const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
    });
    return res.end();
  }
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  for (const r of routes) {
    if (r.method !== req.method) continue;
    const match = url.pathname.match(r.regex);
    if (!match) continue;
    const params = {};
    r.paramNames.forEach((name, i) => { params[name] = decodeURIComponent(match[i + 1]); });
    try {
      await r.handler(req, res, url.searchParams, params);
    } catch (err) {
      console.error('Route error:', err);
      if (!res.headersSent) send(res, 500, { error: 'server_error', message: err.message });
    }
    return;
  }
  send(res, 404, { error: 'not_found' });
});

server.listen(PORT, () => {
  console.log(`ULTRA Message server listening on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
});
