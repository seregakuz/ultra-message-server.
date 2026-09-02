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

// ---------- ОГРАНИЧЕНИЯ РАЗМЕРА ----------
// Без них любое поле можно раздуть почти до предела тела запроса (8 МБ) —
// один недобросовестный клиент может так распухнуть db.json на диске.
const LIMITS = {
  name: 80, username: 32, bio: 500, password: 200,
  avatarPhoto: 2 * 1024 * 1024,   // ~2 МБ строкой base64
  userData: 5 * 1024 * 1024,      // весь блок контактов/чатов/стикеров одного пользователя
  message: 4000
};

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
// Обычное !== выдаёт секрет по времени сравнения (чем больше совпадающих
// символов в начале — тем дольше ответ). Используем для инвайт-кода то же,
// что и для паролей.
function timingSafeStringEqual(a, b){
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA); // всё равно тратим время, чтобы не выдать разницу в длине
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// ---------- ВСПОМОГАТЕЛЬНОЕ ----------
function normalizeUsername(u){
  return (u || '').trim().replace(/^@/, '').toLowerCase();
}
function digitsOnly(s){
  return (s || '').replace(/\D/g, '');
}
// Разрешённые форматы номера — те же правила, что и в клиенте, плюс защита
// от мусорных номеров вида "5555555555" или "66555555555" (верная длина, но не номер).
const PHONE_TOTAL_LENGTH_BY_CODE = {
  '20': 12, '27': 11, '49': 12, '33': 10, '55': 13, '52': 12,
  '61': 11, '66': 11, '86': 13, '81': 12, '91': 12
};
function looksLikeFakeNumber(nationalDigits){
  if (!nationalDigits) return true;
  const counts = {};
  for (const d of nationalDigits) counts[d] = (counts[d] || 0) + 1;
  if (Object.keys(counts).length <= 2) return true;
  const maxCount = Math.max.apply(null, Object.values(counts));
  return (maxCount / nationalDigits.length) >= 0.8;
}
function isValidPhoneFormat(phoneRaw){
  const raw = (phoneRaw || '').trim();
  const digits = digitsOnly(raw);
  if (!digits) return false;
  if (!raw.startsWith('+')) {
    return raw.startsWith('8') && digits.length === 11 && !looksLikeFakeNumber(digits.slice(1));
  }
  if (digits.startsWith('1') || digits.startsWith('7')) {
    return digits.length === 11 && !looksLikeFakeNumber(digits.slice(1));
  }
  const code2 = digits.slice(0, 2);
  if (Object.prototype.hasOwnProperty.call(PHONE_TOTAL_LENGTH_BY_CODE, code2)) {
    return digits.length === PHONE_TOTAL_LENGTH_BY_CODE[code2] && !looksLikeFakeNumber(digits.slice(2));
  }
  if (digits.length < 8 || digits.length > 15) return false;
  for (const codeLen of [3, 2, 1]) {
    if (digits.length - codeLen >= 6 && !looksLikeFakeNumber(digits.slice(codeLen))) return true;
  }
  return false;
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
function clampColorIndex(n){
  return Number.isInteger(n) && n >= 0 && n <= 5 ? n : 0;
}
// Поиск человека — строго по логину, и только если правильно набраны хотя бы
// ~75% его длины с самого начала (а не любой обрывок логина где угодно).
function usernamePrefixMatch(username, term){
  const uname = (username || '').toLowerCase();
  const q = (term || '').toLowerCase().replace(/^@/, '');
  if (!uname || !q) return false;
  const minLen = Math.max(2, Math.ceil(uname.length * 0.75));
  if (q.length < minLen) return false;
  const overlapLen = Math.min(q.length, uname.length);
  return q.slice(0, overlapLen) === uname.slice(0, overlapLen);
}

// Render (и Cloudflare перед ним) передают настоящий IP клиента в этом заголовке —
// req.socket.remoteAddress тут всегда будет адресом прокси, а не человека.
function getClientIp(req){
  const xff = req.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  return req.socket.remoteAddress;
}

// Простая защита от перебора пароля и спам-регистраций: N попыток за окно времени с одного IP.
const rateLimitHits = new Map(); // ip -> [timestamps]
function isRateLimited(ip, limit, windowMs){
  const now = Date.now();
  const hits = (rateLimitHits.get(ip) || []).filter(t => now - t < windowMs);
  hits.push(now);
  rateLimitHits.set(ip, hits);
  if (hits.length > 500) rateLimitHits.set(ip, hits.slice(-500)); // не даём карте расти бесконечно для одного IP
  return hits.length > limit;
}
// Без этого rateLimitHits копит ключи (по IP и по user.id) вечно, пока жив процесс —
// раз в час выбрасываем тех, кто дольше часа ничего не делал.
setInterval(() => {
  const cutoff = Date.now() - 60 * 60 * 1000;
  for (const [key, hits] of rateLimitHits) {
    if (!hits.length || hits[hits.length - 1] < cutoff) rateLimitHits.delete(key);
  }
}, 30 * 60 * 1000).unref();

function findUserByToken(token){
  if (!token) return null;
  const session = db.sessions.find(s => s.token === token);
  if (!session) return null;
  return db.users.find(u => u.id === session.userId) || null;
}

// ---------- HTTP-ОТВЕТЫ ----------
// CORS специально открыт всем (*): клиент — обычный HTML-файл, который открывают
// как угодно (с диска, с любого хостинга), заранее неизвестного origin нет.
// Остальные заголовки ниже сужают то, что реально можно сузить без вреда для этого.
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=15552000; includeSubDomains'
};
function send(res, status, body){
  const json = JSON.stringify(body);
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(json),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
  }, SECURITY_HEADERS));
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

// Если задано, сервер становится приватным: зарегистрироваться может только тот, кто знает этот код.
// Пустое значение (по умолчанию) = сервер открыт для всех, как раньше.
const REGISTRATION_SECRET = process.env.REGISTRATION_SECRET || '';

route('GET', '/api/health', async (req, res) => {
  send(res, 200, { ok: true, users: db.users.length, uptime: process.uptime(), inviteRequired: !!REGISTRATION_SECRET });
});

route('POST', '/api/register', async (req, res) => {
  const ip = getClientIp(req);
  if (isRateLimited(ip, 10, 10 * 60 * 1000)) {
    return send(res, 429, { error: 'rate_limited', message: 'Слишком много попыток регистрации. Попробуйте позже.' });
  }
  const body = await readBody(req);
  if (REGISTRATION_SECRET && !timingSafeStringEqual(body.inviteCode || '', REGISTRATION_SECRET)) {
    return send(res, 403, { error: 'invite_required', message: 'Нужен код приглашения, чтобы зарегистрироваться на этом сервере' });
  }
  const name = (body.name || '').trim();
  const username = (body.username || '').trim();
  const phone = (body.phone || '').trim();
  const password = body.password || '';
  const colorIndex = clampColorIndex(body.colorIndex);

  if (!name || !username || !phone || password.length < 6) {
    return send(res, 400, { error: 'invalid_input', message: 'Заполните имя, логин, телефон и пароль (минимум 6 символов)' });
  }
  if (name.length > LIMITS.name || username.length > LIMITS.username || password.length > LIMITS.password) {
    return send(res, 400, { error: 'too_long', message: 'Слишком длинное значение одного из полей' });
  }
  if (!isValidPhoneFormat(phone)) {
    return send(res, 400, { error: 'invalid_phone', message: 'Неверный формат номера телефона' });
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
  const ip = getClientIp(req);
  if (isRateLimited(ip, 15, 10 * 60 * 1000)) {
    return send(res, 429, { error: 'rate_limited', message: 'Слишком много попыток входа. Попробуйте позже.' });
  }
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
  if (isRateLimited('profile:' + user.id, 30, 5 * 60 * 1000)) {
    return send(res, 429, { error: 'rate_limited' });
  }
  const body = await readBody(req);
  if (typeof body.name === 'string' && body.name.trim()) {
    if (body.name.trim().length > LIMITS.name) return send(res, 400, { error: 'too_long', message: 'Слишком длинное имя' });
    user.name = body.name.trim();
  }
  if (typeof body.username === 'string' && body.username.trim()) {
    if (body.username.trim().length > LIMITS.username) return send(res, 400, { error: 'too_long', message: 'Слишком длинный логин' });
    const newKey = normalizeUsername(body.username);
    const taken = db.users.some(u => u.id !== user.id && u.usernameKey === newKey);
    if (taken) return send(res, 409, { error: 'username_taken', message: 'Этот логин уже занят' });
    user.username = body.username.trim();
    user.usernameKey = newKey;
  }
  if (typeof body.bio === 'string') {
    if (body.bio.length > LIMITS.bio) return send(res, 400, { error: 'too_long', message: 'Слишком длинное описание' });
    user.bio = body.bio;
  }
  if (Number.isInteger(body.colorIndex)) user.colorIndex = clampColorIndex(body.colorIndex);
  if (typeof body.avatarPhoto === 'string' || body.avatarPhoto === null) {
    if (typeof body.avatarPhoto === 'string' && body.avatarPhoto.length > LIMITS.avatarPhoto) {
      return send(res, 400, { error: 'too_long', message: 'Фото профиля слишком большое' });
    }
    user.avatarPhoto = body.avatarPhoto;
  }
  if (typeof body.phonePrivate === 'boolean') user.phonePrivate = body.phonePrivate;
  saveDb();
  send(res, 200, { user: meUser(user) });
});

async function handleSaveData(req, res, query){
  const user = findUserByToken(getToken(req, query));
  if (!user) return send(res, 401, { error: 'unauthorized' });
  if (isRateLimited('data:' + user.id, 40, 5 * 60 * 1000)) {
    return send(res, 429, { error: 'rate_limited' });
  }
  const body = await readBody(req);
  const serialized = body.data ? JSON.stringify(body.data) : '';
  if (serialized.length > LIMITS.userData) {
    return send(res, 400, { error: 'too_long', message: 'Слишком много данных для сохранения' });
  }
  user.data = body.data || null;
  saveDb();
  send(res, 200, { ok: true });
}
route('PUT', '/api/me/data', handleSaveData);
// navigator.sendBeacon умеет отправлять только POST — отдельный маршрут для сохранения при закрытии вкладки
route('POST', '/api/me/data', handleSaveData);

route('GET', '/api/users/search', async (req, res, query) => {
  const user = findUserByToken(getToken(req));
  if (!user) return send(res, 401, { error: 'unauthorized' });
  // Лимит на самого пользователя (не только по IP) — не даёт даже одному живому аккаунту
  // перебрать много запросов подряд и собрать так весь список пользователей.
  if (isRateLimited('search:' + user.id, 30, 5 * 60 * 1000)) {
    return send(res, 429, { error: 'rate_limited', message: 'Слишком много запросов поиска. Подождите немного.' });
  }
  const term = normalizeUsername(query.get('q') || '');
  if (!term) return send(res, 200, { users: [] });
  const results = db.users
    .filter(u => u.id !== user.id)
    .filter(u => usernamePrefixMatch(u.username, term))
    .slice(0, 20)
    .map(publicUser);
  send(res, 200, { users: results });
});

route('GET', '/api/dm/:otherId', async (req, res, query, params) => {
  const user = findUserByToken(getToken(req));
  if (!user) return send(res, 401, { error: 'unauthorized' });
  if (isRateLimited('dm-read:' + user.id, 120, 5 * 60 * 1000)) {
    return send(res, 429, { error: 'rate_limited' });
  }
  const otherId = parseInt(params.otherId, 10);
  const other = db.users.find(u => u.id === otherId);
  if (!other) return send(res, 404, { error: 'not_found' });
  const key = conversationKey(user.id, otherId);
  const since = parseInt(query.get('since') || '0', 10);
  const messages = db.messages.filter(m => m.conversationKey === key && m.id > since);
  // otherUser сюда специально не кладём: иначе можно перебирать id подряд (1,2,3…) и
  // так насобирать данные всех пользователей вообще без переписки с ними.
  send(res, 200, { messages });
});

route('POST', '/api/dm/:otherId', async (req, res, query, params) => {
  const user = findUserByToken(getToken(req));
  if (!user) return send(res, 401, { error: 'unauthorized' });
  if (isRateLimited('dm-write:' + user.id, 60, 5 * 60 * 1000)) {
    return send(res, 429, { error: 'rate_limited' });
  }
  const otherId = parseInt(params.otherId, 10);
  const other = db.users.find(u => u.id === otherId);
  if (!other) return send(res, 404, { error: 'not_found' });
  const body = await readBody(req);
  const text = (body.text || '').trim();
  if (!text) return send(res, 400, { error: 'empty_message' });
  if (text.length > LIMITS.message) return send(res, 400, { error: 'too_long', message: 'Слишком длинное сообщение' });
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
    res.writeHead(204, Object.assign({
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
    }, SECURITY_HEADERS));
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
      if (res.headersSent) return;
      if (err.message === 'payload_too_large') return send(res, 413, { error: 'payload_too_large', message: 'Слишком большой запрос' });
      if (err.message === 'invalid_json') return send(res, 400, { error: 'invalid_json', message: 'Некорректный JSON' });
      // Внутренние детали ошибки наружу не отдаём — только в лог сервера.
      console.error('Route error:', err);
      send(res, 500, { error: 'server_error', message: 'Внутренняя ошибка сервера' });
    }
    return;
  }
  send(res, 404, { error: 'not_found' });
});

// Защита от медленных/зависших соединений (slowloris-подобные атаки): рвём то,
// что не укладывается в разумное время на заголовки/тело/простой запрос.
server.headersTimeout = 15_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 20_000;
server.maxConnections = 2000;

server.listen(PORT, () => {
  console.log(`ULTRA Message server listening on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
});
