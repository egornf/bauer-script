'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT_DIR = __dirname;
const INDEX_PATH = path.join(ROOT_DIR, 'index.html');
const DEFAULT_DATA_DIR = path.join(ROOT_DIR, 'data');

const SESSION_COOKIE = 'bauer_sid';
const CSRF_COOKIE = 'bauer_csrf';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_BODY_BYTES = 12 * 1024 * 1024; // 12 MB (for base64 gift photos in layouts/content)

const ALL_PERMISSIONS = [
  'content.edit',
  'layouts.manage',
  'gifts.manage',
  'addresses.manage',
  'settings.manage',
  'users.view',
  'audit.view'
];

const DEFAULT_ROLE_PERMISSIONS = {
  OWNER: [...ALL_PERMISSIONS, 'users.manage', 'admins.manage', 'sessions.manage', 'owner.full'],
  ADMIN: ['content.edit', 'layouts.manage', 'gifts.manage', 'addresses.manage', 'settings.manage'],
  EDITOR: ['content.edit', 'layouts.manage', 'gifts.manage', 'addresses.manage'],
  OPERATOR: []
};

const DEFAULT_OWNER_USER = {
  "id": "usr_owner_melentyev_ea",
  "login": "МелентьевЕА",
  "displayName": "Мелентьев Е.А.",
  "role": "OWNER",
  "passwordHash": "scrypt$16384$8$1$0fdf9fa25649ad4b8df72268798a79c0$e6be6c83790f1e583c8992338cb571975faf8b4566bef6393fdf2f42f8970131289d940eabd62ca8086c0d4aef6208139a225831491d51e85786ec5d91705204",
  "blocked": false,
  "permissions": [
    "content.edit",
    "layouts.manage",
    "gifts.manage",
    "addresses.manage",
    "settings.manage",
    "users.view",
    "audit.view",
    "users.manage",
    "admins.manage",
    "sessions.manage",
    "owner.full"
  ],
  "recoverySalt": "162cd43facda08bbafa57045e1021526",
  "recoveryCodes": [
    {
      "id": 1,
      "hash": "25784949ae7bf50721d19844971bdc7a3123ccaecd8641812c07af5580841b82",
      "used": false,
      "usedAt": null
    },
    {
      "id": 2,
      "hash": "26b251ee262ed71d38a204c61b792ca2192e84f72683dcd5f7efd4408077b05c",
      "used": false,
      "usedAt": null
    },
    {
      "id": 3,
      "hash": "e6a149ee4e5142b0e4e582be3bd8cc9737efa12937ea4a1ca1fa7c543ad50de9",
      "used": false,
      "usedAt": null
    },
    {
      "id": 4,
      "hash": "11ee1b05df646928fecb6f4708174b99dfea42441f158f789a2c723ae3dd2041",
      "used": false,
      "usedAt": null
    },
    {
      "id": 5,
      "hash": "1ac34eb10d33efc0b24e3586dcc20130294739da02386d85e4f1bfe3b4fe7884",
      "used": false,
      "usedAt": null
    },
    {
      "id": 6,
      "hash": "c6e4e1ac2466463ed6ebad44a15e228efd6f561bed96c5927fbb9581f189ecfb",
      "used": false,
      "usedAt": null
    }
  ],
  "createdAt": 1793519400000,
  "updatedAt": 1793519400000,
  "lastLoginAt": null
};

function normalizeLogin(login) {
  return String(login || '').trim().toLocaleLowerCase('ru');
}

function validateLogin(login) {
  const trimmed = String(login || '').trim();
  return /^[a-zA-Zа-яА-ЯёЁ0-9_.\-\s]{2,64}$/u.test(trimmed) ? trimmed : null;
}

function validatePassword(password) {
  return typeof password === 'string' && password.length >= 4 && password.length <= 128;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const N = 16384, r = 8, p = 1, keylen = 64;
  const derived = crypto.scryptSync(String(password), salt, keylen, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${salt.toString('hex')}$${derived.toString('hex')}`;
}

function verifyPassword(password, storedHash) {
  if (typeof password !== 'string' || typeof storedHash !== 'string') return false;
  const parts = storedHash.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = Number(parts[1]), r = Number(parts[2]), p = Number(parts[3]);
  const salt = Buffer.from(parts[4], 'hex');
  const expected = Buffer.from(parts[5], 'hex');
  if (!salt.length || !expected.length) return false;
  try {
    const actual = crypto.scryptSync(password, salt, expected.length, { N, r, p });
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function generateRecoveryCodes(count = 6) {
  const codes = [];
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  for (let i = 0; i < count; i++) {
    const bytes = crypto.randomBytes(12);
    let chars = '';
    for (let j = 0; j < 12; j++) {
      chars += alphabet[bytes[j] % alphabet.length];
    }
    codes.push(`${chars.slice(0, 4)}-${chars.slice(4, 8)}-${chars.slice(8, 12)}`);
  }
  return codes;
}

function normalizeRecoveryCode(code) {
  return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function hashRecoveryCode(code, saltHex) {
  const norm = normalizeRecoveryCode(code);
  return crypto.scryptSync(norm, Buffer.from(saltHex, 'hex'), 32, { N: 16384, r: 8, p: 1 }).toString('hex');
}

function extractSeedFromIndexHtml(htmlPath = INDEX_PATH) {
  const seed = {
    content: null,
    layouts: [],
    addresses: { revision: 0, venues: [] },
    gifts: []
  };
  try {
    const html = fs.readFileSync(htmlPath, 'utf8');
    const matchTag = (id) => {
      const re = new RegExp(`<script\\s+id=["']${id}["'][^>]*>([\\s\\S]*?)<\\/script>`, 'i');
      const m = html.match(re);
      return m ? JSON.parse(m[1]) : null;
    };
    const scriptData = matchTag('script-data');
    const layoutsData = matchTag('layouts-data');
    const smsData = matchTag('sms-data');

    if (scriptData && typeof scriptData === 'object') {
      seed.content = { data: scriptData, updatedAt: Number(scriptData.updatedAt) || Date.now() };
      if (Array.isArray(scriptData.gifts)) {
        seed.gifts.push(...scriptData.gifts);
      }
    }
    if (Array.isArray(layoutsData)) {
      seed.layouts = layoutsData;
      for (const l of layoutsData) {
        if (l && l.data && Array.isArray(l.data.gifts)) {
          for (const g of l.data.gifts) {
            if (g && g.id && !seed.gifts.some(x => x.id === g.id)) {
              seed.gifts.push(g);
            }
          }
        }
      }
    }
    if (smsData && Array.isArray(smsData.venues)) {
      seed.addresses = { revision: 0, venues: smsData.venues };
    }
  } catch (err) {
    console.warn('Warning: could not parse seed from index.html:', err.message);
  }
  return seed;
}

function createStore(dataDir = DEFAULT_DATA_DIR, htmlPath = INDEX_PATH, seedDefaultOwner = true) {
  fs.mkdirSync(dataDir, { recursive: true });
  const files = {
    users: path.join(dataDir, 'users.json'),
    sessions: path.join(dataDir, 'sessions.json'),
    audit: path.join(dataDir, 'audit.json'),
    appData: path.join(dataDir, 'app-data.json')
  };

  function readJson(filePath, fallback) {
    try {
      if (!fs.existsSync(filePath)) return fallback;
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch {
      return fallback;
    }
  }

  function writeJsonAtomic(filePath, data) {
    const tmp = `${filePath}.${process.pid}.${Date.now()}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmp, filePath);
  }

  let users = readJson(files.users, []);
  let sessions = readJson(files.sessions, []);
  let audit = readJson(files.audit, []);
  let appData = readJson(files.appData, null);

  if (!appData) {
    const seed = extractSeedFromIndexHtml(htmlPath);
    appData = {
      content: seed.content || { data: null, updatedAt: 0 },
      layouts: seed.layouts || [],
      addresses: seed.addresses || { revision: 0, venues: [] },
      giftbase: { gifts: seed.gifts || [], deleted: [], updatedAt: Date.now() }
    };
    writeJsonAtomic(files.appData, appData);
  }

  if (seedDefaultOwner && !users.some(u => u.role === 'OWNER')) {
    users.unshift(structuredClone(DEFAULT_OWNER_USER));
    writeJsonAtomic(files.users, users);
  }
  // Enforce single OWNER invariant on load
  const owners = users.filter(u => u.role === 'OWNER');
  if (owners.length > 1) {
    const primaryOwner = owners.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0))[0];
    users.forEach(u => {
      if (u.role === 'OWNER' && u.id !== primaryOwner.id) {
        u.role = 'ADMIN';
      }
    });
    writeJsonAtomic(files.users, users);
  }
  if (owners.length >= 1) {
    const owner = owners[0];
    owner.blocked = false;
    owner.permissions = [...DEFAULT_ROLE_PERMISSIONS.OWNER];
  }

  function saveUsers() {
    const ownerCount = users.filter(u => u.role === 'OWNER').length;
    if (ownerCount > 1) {
      throw new Error('Нарушение инварианта: в системе может быть только один OWNER.');
    }
    writeJsonAtomic(files.users, users);
  }

  function saveSessions() {
    writeJsonAtomic(files.sessions, sessions);
  }

  function saveAudit() {
    if (audit.length > 2500) {
      audit = audit.slice(-2500);
    }
    writeJsonAtomic(files.audit, audit);
  }

  function saveAppData() {
    writeJsonAtomic(files.appData, appData);
  }

  function logEvent({ action, actor, target = null, ip = '', userAgent = '', details = {}, status = 'success' }) {
    const entry = {
      id: 'ev_' + crypto.randomUUID(),
      timestamp: Date.now(),
      action,
      status,
      actorId: actor?.id || null,
      actorLogin: actor?.login || (typeof actor === 'string' ? actor : 'anonymous'),
      actorRole: actor?.role || null,
      target,
      ip: String(ip || '').slice(0, 100),
      userAgent: String(userAgent || '').slice(0, 250),
      details
    };
    audit.push(entry);
    saveAudit();
    return entry;
  }

  function cleanExpiredSessions() {
    const now = Date.now();
    const before = sessions.length;
    sessions = sessions.filter(s => s.expiresAt > now && !s.revoked);
    if (sessions.length !== before) saveSessions();
  }

  return {
    getUsers: () => users,
    getOwner: () => users.find(u => u.role === 'OWNER') || null,
    findUserById: (id) => users.find(u => u.id === id) || null,
    findUserByLogin: (login) => {
      const norm = normalizeLogin(login);
      return users.find(u => normalizeLogin(u.login) === norm) || null;
    },
    addUser: (user) => {
      if (user.role === 'OWNER' && users.some(u => u.role === 'OWNER')) {
        throw new Error('В системе уже существует учётная запись OWNER.');
      }
      users.push(user);
      saveUsers();
      return user;
    },
    removeUser: (id) => {
      const u = users.find(x => x.id === id);
      if (!u) return false;
      if (u.role === 'OWNER') {
        throw new Error('Невозможно удалить главную учётную запись OWNER.');
      }
      users = users.filter(x => x.id !== id);
      sessions = sessions.filter(s => s.userId !== id);
      saveUsers();
      saveSessions();
      return true;
    },
    saveUsers,
    getSessions: () => {
      cleanExpiredSessions();
      return sessions;
    },
    createSession: (user, { ip, userAgent }) => {
      cleanExpiredSessions();
      const rawToken = crypto.randomBytes(32).toString('hex');
      const csrfToken = crypto.randomBytes(24).toString('hex');
      const now = Date.now();
      const session = {
        id: 'ses_' + crypto.randomUUID(),
        tokenHash: hashToken(rawToken),
        csrfToken,
        userId: user.id,
        userLogin: user.login,
        userRole: user.role,
        ip: String(ip || '').slice(0, 100),
        userAgent: String(userAgent || '').slice(0, 250),
        createdAt: now,
        lastActiveAt: now,
        expiresAt: now + SESSION_TTL_MS,
        revoked: false
      };
      sessions.push(session);
      saveSessions();
      return { rawToken, session };
    },
    findSessionByToken: (rawToken) => {
      if (!rawToken) return null;
      cleanExpiredSessions();
      const th = hashToken(rawToken);
      const s = sessions.find(x => x.tokenHash === th && !x.revoked);
      if (!s) return null;
      const u = users.find(x => x.id === s.userId);
      if (!u || (u.blocked && u.role !== 'OWNER')) {
        s.revoked = true;
        saveSessions();
        return null;
      }
      return { session: s, user: u };
    },
    touchSession: (session) => {
      const now = Date.now();
      if (now - session.lastActiveAt > 30000) {
        session.lastActiveAt = now;
        saveSessions();
      }
    },
    revokeSessionById: (sessionId) => {
      const idx = sessions.findIndex(s => s.id === sessionId);
      if (idx < 0) return null;
      const [removed] = sessions.splice(idx, 1);
      saveSessions();
      return removed;
    },
    revokeUserSessions: (userId, exceptSessionId = null) => {
      const before = sessions.length;
      sessions = sessions.filter(s => s.userId !== userId || (exceptSessionId && s.id === exceptSessionId));
      const count = before - sessions.length;
      if (count > 0) saveSessions();
      return count;
    },
    getAudit: () => audit,
    logEvent,
    getAppData: () => appData,
    saveAppData
  };
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx > 0) {
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      try {
        out[k] = decodeURIComponent(v);
      } catch {
        out[k] = v;
      }
    }
  });
  return out;
}

function serializeCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${options.path || '/'}`);
  if (options.httpOnly) parts.push('HttpOnly');
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (options.maxAge !== undefined) parts.push(`Max-Age=${Math.floor(options.maxAge)}`);
  return parts.join('; ');
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim()) {
    return xff.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || '127.0.0.1';
}

function hasPermission(user, perm) {
  if (!user) return false;
  if (user.role === 'OWNER') return true;
  if (user.blocked) return false;
  const perms = Array.isArray(user.permissions) ? user.permissions : (DEFAULT_ROLE_PERMISSIONS[user.role] || []);
  return perms.includes(perm);
}

function sanitizeUser(u) {
  if (!u) return null;
  const isOwner = u.role === 'OWNER';
  return {
    id: u.id,
    login: u.login,
    displayName: u.displayName || u.login,
    role: u.role,
    blocked: isOwner ? false : Boolean(u.blocked),
    permissions: isOwner ? [...DEFAULT_ROLE_PERMISSIONS.OWNER] : (Array.isArray(u.permissions) ? u.permissions : []),
    createdAt: u.createdAt || 0,
    updatedAt: u.updatedAt || 0,
    lastLoginAt: u.lastLoginAt || null,
    recoveryCodesRemaining: isOwner && Array.isArray(u.recoveryCodes) ? u.recoveryCodes.filter(c => !c.used).length : undefined
  };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', chunk => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('Превышен допустимый размер запроса.'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw.trim()) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(Object.assign(new Error('Некорректный формат JSON.'), { status: 400 }));
      }
    });
    req.on('error', err => reject(err));
  });
}

function sendJson(res, status, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    ...extraHeaders
  });
  res.end(body);
}

function createAppServer(options = {}) {
  const dataDir = options.dataDir || DEFAULT_DATA_DIR;
  const htmlPath = options.htmlPath || INDEX_PATH;
  const store = createStore(dataDir, htmlPath, options.seedDefaultOwner !== false);

  // Brute-force rate limiter in memory
  const loginAttempts = new Map(); // key -> { count, resetAt }

  function checkRateLimit(key, maxAttempts = 10, windowMs = 10 * 60 * 1000) {
    const now = Date.now();
    const rec = loginAttempts.get(key);
    if (!rec || now > rec.resetAt) {
      loginAttempts.set(key, { count: 1, resetAt: now + windowMs });
      return true;
    }
    rec.count += 1;
    if (rec.count > maxAttempts) {
      return false;
    }
    return true;
  }

  function clearRateLimit(key) {
    loginAttempts.delete(key);
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;
    const method = (req.method || 'GET').toUpperCase();
    const ip = getClientIp(req);
    const userAgent = req.headers['user-agent'] || '';

    try {
      // Static files
      if (!pathname.startsWith('/api/')) {
        if (method !== 'GET' && method !== 'HEAD') {
          return sendJson(res, 405, { error: 'Метод не поддерживается.' });
        }
        if (pathname === '/' || pathname === '/index.html') {
          const html = fs.readFileSync(htmlPath, 'utf8');
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-cache',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN'
          });
          res.end(method === 'HEAD' ? undefined : html);
          return;
        }
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Не найдено');
        return;
      }

      const cookies = parseCookies(req);
      const auth = store.findSessionByToken(cookies[SESSION_COOKIE]);
      if (auth) {
        store.touchSession(auth.session);
      }

      // CSRF verification for state-changing requests with an active session
      const isMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
      const isPublicAuthRoute = ['/api/admin/login', '/api/admin/setup', '/api/owner/recover'].includes(pathname);
      if (isMutating && auth && !isPublicAuthRoute) {
        const csrfHeader = req.headers['x-csrf-token'];
        if (!csrfHeader || csrfHeader !== auth.session.csrfToken) {
          return sendJson(res, 403, { error: 'Ошибка проверки безопасности сессии (CSRF). Обновите страницу.' });
        }
      }

      // 1. GET /api/admin/status
      if (pathname === '/api/admin/status' && method === 'GET') {
        const owner = store.getOwner();
        const configured = Boolean(owner);
        const user = auth ? sanitizeUser(auth.user) : null;
        return sendJson(res, 200, {
          unlocked: Boolean(auth),
          configured,
          signedIn: true,
          canSetup: !configured,
          user,
          sessionId: auth?.session?.id || null,
          csrfToken: auth?.session?.csrfToken || null,
          availablePermissions: ALL_PERMISSIONS,
          roleDefaults: DEFAULT_ROLE_PERMISSIONS
        });
      }

      // 2. POST /api/admin/setup (Initial OWNER creation — only when no OWNER exists)
      if (pathname === '/api/admin/setup' && method === 'POST') {
        if (store.getOwner()) {
          store.logEvent({
            action: 'owner.setup.denied',
            actor: auth?.user || 'anonymous',
            ip,
            userAgent,
            status: 'denied',
            details: { reason: 'OWNER already exists' }
          });
          return sendJson(res, 403, { error: 'Главная учётная запись OWNER уже создана. В системе может быть только один OWNER.' });
        }
        const body = await readBody(req);
        const login = validateLogin(body.login);
        if (!login) {
          return sendJson(res, 400, { error: 'Логин должен содержать от 2 до 64 символов (русские/латинские буквы, цифры, пробел, . _ -).' });
        }
        if (!validatePassword(body.password)) {
          return sendJson(res, 400, { error: 'Пароль должен содержать от 4 до 128 символов.' });
        }
        const rawCodes = generateRecoveryCodes(6);
        const recoverySalt = crypto.randomBytes(16).toString('hex');
        const now = Date.now();
        const ownerUser = {
          id: 'usr_owner_' + crypto.randomUUID(),
          login,
          displayName: String(body.displayName || login).trim().slice(0, 100) || login,
          role: 'OWNER',
          passwordHash: hashPassword(body.password),
          blocked: false,
          permissions: [...DEFAULT_ROLE_PERMISSIONS.OWNER],
          recoverySalt,
          recoveryCodes: rawCodes.map((code, idx) => ({
            id: idx + 1,
            hash: hashRecoveryCode(code, recoverySalt),
            used: false,
            usedAt: null
          })),
          createdAt: now,
          updatedAt: now,
          lastLoginAt: now
        };
        store.addUser(ownerUser);
        const { rawToken, session } = store.createSession(ownerUser, { ip, userAgent });
        store.logEvent({
          action: 'owner.setup',
          actor: ownerUser,
          target: ownerUser.login,
          ip,
          userAgent,
          details: { role: 'OWNER' }
        });
        return sendJson(
          res,
          200,
          {
            ok: true,
            user: sanitizeUser(ownerUser),
            sessionId: session.id,
            csrfToken: session.csrfToken,
            recoveryCodes: rawCodes
          },
          {
            'Set-Cookie': [
              serializeCookie(SESSION_COOKIE, rawToken, { httpOnly: true, sameSite: 'Strict', maxAge: SESSION_TTL_MS / 1000 }),
              serializeCookie(CSRF_COOKIE, session.csrfToken, { httpOnly: false, sameSite: 'Strict', maxAge: SESSION_TTL_MS / 1000 })
            ]
          }
        );
      }

      // 3. POST /api/admin/login
      if (pathname === '/api/admin/login' && method === 'POST') {
        const body = await readBody(req);
        const login = normalizeLogin(body.login);
        const password = String(body.password || '');
        const rateKey = `login:${ip}:${login}`;

        if (!checkRateLimit(rateKey, 10, 10 * 60 * 1000)) {
          store.logEvent({
            action: 'auth.login.rate_limited',
            actor: login || 'anonymous',
            ip,
            userAgent,
            status: 'failed',
            details: { login }
          });
          return sendJson(res, 429, { error: 'Слишком много попыток входа. Подождите 10 минут и попробуйте снова.' });
        }

        if (!store.getOwner()) {
          return sendJson(res, 400, { error: 'Система ещё не инициализирована. Создайте учётную запись OWNER.' });
        }

        const user = store.findUserByLogin(login);
        if (!user || !verifyPassword(password, user.passwordHash)) {
          store.logEvent({
            action: 'auth.login.failed',
            actor: login || 'anonymous',
            target: login,
            ip,
            userAgent,
            status: 'failed',
            details: { reason: !user ? 'user_not_found' : 'invalid_password' }
          });
          return sendJson(res, 401, { error: 'Неверный логин или пароль.' });
        }

        if (user.blocked && user.role !== 'OWNER') {
          store.logEvent({
            action: 'auth.login.blocked',
            actor: user,
            target: user.login,
            ip,
            userAgent,
            status: 'denied',
            details: { reason: 'account_blocked' }
          });
          return sendJson(res, 403, { error: 'Учётная запись заблокирована владельцем системы (OWNER).' });
        }

        clearRateLimit(rateKey);
        user.lastLoginAt = Date.now();
        store.saveUsers();
        const { rawToken, session } = store.createSession(user, { ip, userAgent });
        store.logEvent({
          action: 'auth.login.success',
          actor: user,
          target: user.login,
          ip,
          userAgent,
          details: { sessionId: session.id, role: user.role }
        });

        return sendJson(
          res,
          200,
          {
            ok: true,
            user: sanitizeUser(user),
            sessionId: session.id,
            csrfToken: session.csrfToken
          },
          {
            'Set-Cookie': [
              serializeCookie(SESSION_COOKIE, rawToken, { httpOnly: true, sameSite: 'Strict', maxAge: SESSION_TTL_MS / 1000 }),
              serializeCookie(CSRF_COOKIE, session.csrfToken, { httpOnly: false, sameSite: 'Strict', maxAge: SESSION_TTL_MS / 1000 })
            ]
          }
        );
      }

      // 4. POST /api/admin/logout
      if (pathname === '/api/admin/logout' && method === 'POST') {
        if (auth) {
          store.revokeSessionById(auth.session.id);
          store.logEvent({
            action: 'auth.logout',
            actor: auth.user,
            target: auth.user.login,
            ip,
            userAgent,
            details: { sessionId: auth.session.id }
          });
        }
        return sendJson(
          res,
          200,
          { ok: true },
          {
            'Set-Cookie': [
              serializeCookie(SESSION_COOKIE, '', { httpOnly: true, sameSite: 'Strict', maxAge: 0 }),
              serializeCookie(CSRF_COOKIE, '', { httpOnly: false, sameSite: 'Strict', maxAge: 0 })
            ]
          }
        );
      }

      // 5. POST /api/owner/recover (Secure OWNER recovery using one-time recovery code)
      if (pathname === '/api/owner/recover' && method === 'POST') {
        const rateKey = `recover:${ip}`;
        if (!checkRateLimit(rateKey, 5, 15 * 60 * 1000)) {
          store.logEvent({
            action: 'owner.recovery.rate_limited',
            actor: 'anonymous',
            ip,
            userAgent,
            status: 'failed'
          });
          return sendJson(res, 429, { error: 'Слишком много попыток восстановления. Повторите через 15 минут.' });
        }

        const owner = store.getOwner();
        if (!owner) {
          return sendJson(res, 400, { error: 'Учётная запись OWNER ещё не создана.' });
        }

        const body = await readBody(req);
        const login = normalizeLogin(body.login);
        const recoveryCode = normalizeRecoveryCode(body.recoveryCode);
        const newPassword = body.newPassword;
        const newLogin = body.newLogin ? validateLogin(body.newLogin) : owner.login;

        if (login !== normalizeLogin(owner.login)) {
          store.logEvent({
            action: 'owner.recovery.failed',
            actor: login || 'anonymous',
            target: owner.login,
            ip,
            userAgent,
            status: 'failed',
            details: { reason: 'login_mismatch' }
          });
          return sendJson(res, 401, { error: 'Неверный логин OWNER или код восстановления.' });
        }

        if (!recoveryCode || recoveryCode.length < 8 || !owner.recoverySalt || !Array.isArray(owner.recoveryCodes)) {
          return sendJson(res, 401, { error: 'Неверный логин OWNER или код восстановления.' });
        }

        if (!validatePassword(newPassword)) {
          return sendJson(res, 400, { error: 'Новый пароль должен содержать от 4 до 128 символов.' });
        }
        if (!newLogin) {
          return sendJson(res, 400, { error: 'Некорректный формат нового логина.' });
        }
        if (normalizeLogin(newLogin) !== normalizeLogin(owner.login) && store.findUserByLogin(newLogin)) {
          return sendJson(res, 400, { error: 'Этот логин уже занят другим пользователем.' });
        }

        const candidateHash = hashRecoveryCode(recoveryCode, owner.recoverySalt);
        const matchedCode = owner.recoveryCodes.find(c => {
          if (c.used || !c.hash) return false;
          const a = Buffer.from(c.hash, 'hex');
          const b = Buffer.from(candidateHash, 'hex');
          return a.length === b.length && crypto.timingSafeEqual(a, b);
        });

        if (!matchedCode) {
          store.logEvent({
            action: 'owner.recovery.failed',
            actor: owner,
            target: owner.login,
            ip,
            userAgent,
            status: 'failed',
            details: { reason: 'invalid_or_used_recovery_code' }
          });
          return sendJson(res, 401, { error: 'Неверный или уже использованный резервный код восстановления.' });
        }

        clearRateLimit(rateKey);
        matchedCode.used = true;
        matchedCode.usedAt = Date.now();
        owner.passwordHash = hashPassword(newPassword);
        owner.login = newLogin;
        owner.blocked = false;
        owner.updatedAt = Date.now();
        owner.lastLoginAt = Date.now();
        store.saveUsers();

        // Terminate all old sessions of OWNER on recovery
        store.revokeUserSessions(owner.id);
        const { rawToken, session } = store.createSession(owner, { ip, userAgent });

        store.logEvent({
          action: 'owner.recovery.success',
          actor: owner,
          target: owner.login,
          ip,
          userAgent,
          details: { codeId: matchedCode.id, remainingCodes: owner.recoveryCodes.filter(c => !c.used).length }
        });

        return sendJson(
          res,
          200,
          {
            ok: true,
            user: sanitizeUser(owner),
            sessionId: session.id,
            csrfToken: session.csrfToken,
            remainingRecoveryCodes: owner.recoveryCodes.filter(c => !c.used).length
          },
          {
            'Set-Cookie': [
              serializeCookie(SESSION_COOKIE, rawToken, { httpOnly: true, sameSite: 'Strict', maxAge: SESSION_TTL_MS / 1000 }),
              serializeCookie(CSRF_COOKIE, session.csrfToken, { httpOnly: false, sameSite: 'Strict', maxAge: SESSION_TTL_MS / 1000 })
            ]
          }
        );
      }

      // 6. Public read endpoints for BAUER operator workspace + authenticated write endpoints
      const appData = store.getAppData();

      if (pathname === '/api/content') {
        if (method === 'GET') {
          return sendJson(res, 200, appData.content || { data: null, updatedAt: 0 });
        }
        if (method === 'PUT') {
          if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
          if (!hasPermission(auth.user, 'content.edit')) {
            store.logEvent({ action: 'content.update.denied', actor: auth.user, ip, userAgent, status: 'denied' });
            return sendJson(res, 403, { error: 'Недостаточно прав для публикации изменений скрипта.' });
          }
          const body = await readBody(req);
          if (!body.data || typeof body.data !== 'object') {
            return sendJson(res, 400, { error: 'Некорректные данные скрипта.' });
          }
          const currentSettings = appData.content?.data?.settings;
          if (
            currentSettings &&
            body.data.settings &&
            JSON.stringify(body.data.settings) !== JSON.stringify(currentSettings) &&
            !hasPermission(auth.user, 'settings.manage')
          ) {
            store.logEvent({ action: 'settings.update.denied', actor: auth.user, ip, userAgent, status: 'denied' });
            return sendJson(res, 403, { error: 'Недостаточно прав для изменения настроек оформления (settings.manage).' });
          }
          const updatedAt = Date.now();
          appData.content = { data: { ...body.data, gifts: [] }, updatedAt };
          store.saveAppData();
          store.logEvent({
            action: 'content.publish',
            actor: auth.user,
            ip,
            userAgent,
            details: { stagesCount: Array.isArray(body.data.stages) ? body.data.stages.length : 0 }
          });
          return sendJson(res, 200, { updatedAt });
        }
      }

      if (pathname === '/api/scripts' && method === 'GET') {
        return sendJson(res, 200, { layouts: appData.layouts || [] });
      }

      if (pathname === '/api/giftbase') {
        if (method === 'GET') {
          return sendJson(res, 200, appData.giftbase || { gifts: [], deleted: [], updatedAt: 0 });
        }
        if (method === 'PUT') {
          if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
          if (!hasPermission(auth.user, 'gifts.manage')) {
            store.logEvent({ action: 'gifts.update.denied', actor: auth.user, ip, userAgent, status: 'denied' });
            return sendJson(res, 403, { error: 'Недостаточно прав для изменения базы подарков.' });
          }
          const body = await readBody(req);
          const gifts = Array.isArray(body.gifts) ? body.gifts : [];
          const deleted = Array.isArray(body.deleted) ? body.deleted : [];
          appData.giftbase = { gifts, deleted, updatedAt: Date.now() };
          store.saveAppData();
          store.logEvent({
            action: 'gifts.update',
            actor: auth.user,
            ip,
            userAgent,
            details: { giftsCount: gifts.length }
          });
          return sendJson(res, 200, appData.giftbase);
        }
      }

      if (pathname === '/api/addresses') {
        if (method === 'GET') {
          return sendJson(res, 200, appData.addresses || { revision: 0, venues: [] });
        }
        if (method === 'PUT') {
          if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
          if (!hasPermission(auth.user, 'addresses.manage')) {
            store.logEvent({ action: 'addresses.update.denied', actor: auth.user, ip, userAgent, status: 'denied' });
            return sendJson(res, 403, { error: 'Недостаточно прав для редактирования адресов площадок.' });
          }
          const body = await readBody(req);
          if (!Array.isArray(body.venues)) {
            return sendJson(res, 400, { error: 'Некорректный список площадок.' });
          }
          const rev = ((appData.addresses && appData.addresses.revision) || 0) + 1;
          appData.addresses = { revision: rev, venues: body.venues };
          store.saveAppData();
          store.logEvent({
            action: 'addresses.update',
            actor: auth.user,
            ip,
            userAgent,
            details: { venuesCount: body.venues.length, revision: rev }
          });
          return sendJson(res, 200, appData.addresses);
        }
      }

      if (pathname === '/api/layouts-order' && method === 'PUT') {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        if (!hasPermission(auth.user, 'layouts.manage')) {
          store.logEvent({ action: 'layouts.reorder.denied', actor: auth.user, ip, userAgent, status: 'denied' });
          return sendJson(res, 403, { error: 'Недостаточно прав для управления макетами.' });
        }
        const body = await readBody(req);
        const ids = Array.isArray(body.ids) ? body.ids : [];
        const all = appData.layouts || [];
        const byId = new Map(all.map(l => [l.id, l]));
        const head = ids.map(i => byId.get(i)).filter(Boolean);
        const rest = all.filter(l => !ids.includes(l.id));
        appData.layouts = [...head, ...rest];
        store.saveAppData();
        store.logEvent({
          action: 'layouts.reorder',
          actor: auth.user,
          ip,
          userAgent,
          details: { count: ids.length }
        });
        return sendJson(res, 200, { ok: true });
      }

      if (pathname === '/api/layouts' || pathname.startsWith('/api/layouts/')) {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        const id = pathname.split('/')[3] || null;
        if (method === 'GET') {
          if (!hasPermission(auth.user, 'content.edit') && !hasPermission(auth.user, 'layouts.manage')) {
            return sendJson(res, 403, { error: 'Недостаточно прав для просмотра редактора макетов.' });
          }
          return sendJson(res, 200, { layouts: appData.layouts || [] });
        }
        if (!hasPermission(auth.user, 'layouts.manage')) {
          store.logEvent({ action: 'layouts.modify.denied', actor: auth.user, ip, userAgent, status: 'denied' });
          return sendJson(res, 403, { error: 'Недостаточно прав для сохранения или удаления макетов.' });
        }
        if (method === 'DELETE') {
          const targetLayout = (appData.layouts || []).find(l => l.id === id);
          appData.layouts = (appData.layouts || []).filter(l => l.id !== id);
          store.saveAppData();
          store.logEvent({
            action: 'layouts.delete',
            actor: auth.user,
            target: targetLayout?.name || id,
            ip,
            userAgent,
            details: { layoutId: id }
          });
          return sendJson(res, 200, { ok: true });
        }
        if (method === 'POST' || method === 'PUT') {
          const body = await readBody(req);
          const layout = {
            id: id || ('l' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex')),
            name: String(body.name || 'Без названия').slice(0, 120),
            data: { ...(body.data || {}), gifts: [] },
            savedAt: Date.now()
          };
          let list = appData.layouts || [];
          if (list.some(l => l.id === layout.id)) {
            list = list.map(l => (l.id === layout.id ? layout : l));
          } else {
            list = [layout, ...list].slice(0, 50);
          }
          appData.layouts = list;
          store.saveAppData();
          store.logEvent({
            action: method === 'POST' ? 'layouts.create' : 'layouts.update',
            actor: auth.user,
            target: layout.name,
            ip,
            userAgent,
            details: { layoutId: layout.id }
          });
          return sendJson(res, 200, { layout });
        }
      }

      // =====================================================================
      // OWNER & USER MANAGEMENT ENDPOINTS (Strict Server-Side Authorization)
      // =====================================================================

      // Self profile & password update for any authenticated user
      if (pathname === '/api/me/password' && method === 'POST') {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        const body = await readBody(req);
        if (!verifyPassword(body.currentPassword, auth.user.passwordHash)) {
          store.logEvent({ action: 'user.password.failed', actor: auth.user, ip, userAgent, status: 'failed' });
          return sendJson(res, 401, { error: 'Текущий пароль введён неверно.' });
        }
        if (!validatePassword(body.newPassword)) {
          return sendJson(res, 400, { error: 'Новый пароль должен содержать от 4 до 128 символов.' });
        }
        auth.user.passwordHash = hashPassword(body.newPassword);
        auth.user.updatedAt = Date.now();
        store.saveUsers();
        store.revokeUserSessions(auth.user.id, auth.session.id);
        store.logEvent({
          action: 'user.password.changed',
          actor: auth.user,
          target: auth.user.login,
          ip,
          userAgent
        });
        return sendJson(res, 200, { ok: true });
      }

      // Regenerate OWNER recovery codes (OWNER only, requires current password)
      if (pathname === '/api/owner/recovery-codes' && method === 'POST') {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        if (auth.user.role !== 'OWNER') {
          store.logEvent({ action: 'owner.recovery_codes.denied', actor: auth.user, ip, userAgent, status: 'denied' });
          return sendJson(res, 403, { error: 'Доступно только владельцу системы (OWNER).' });
        }
        const body = await readBody(req);
        if (!verifyPassword(body.password, auth.user.passwordHash)) {
          store.logEvent({ action: 'owner.recovery_codes.failed', actor: auth.user, ip, userAgent, status: 'failed' });
          return sendJson(res, 401, { error: 'Неверный пароль OWNER.' });
        }
        const rawCodes = generateRecoveryCodes(6);
        const recoverySalt = crypto.randomBytes(16).toString('hex');
        auth.user.recoverySalt = recoverySalt;
        auth.user.recoveryCodes = rawCodes.map((code, idx) => ({
          id: idx + 1,
          hash: hashRecoveryCode(code, recoverySalt),
          used: false,
          usedAt: null
        }));
        auth.user.updatedAt = Date.now();
        store.saveUsers();
        store.logEvent({
          action: 'owner.recovery_codes.regenerated',
          actor: auth.user,
          target: auth.user.login,
          ip,
          userAgent
        });
        return sendJson(res, 200, { ok: true, recoveryCodes: rawCodes });
      }

      // Update OWNER profile (login / displayName) - OWNER only
      if (pathname === '/api/owner/profile' && method === 'PATCH') {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        if (auth.user.role !== 'OWNER') {
          return sendJson(res, 403, { error: 'Доступно только владельцу системы (OWNER).' });
        }
        const body = await readBody(req);
        if (body.login !== undefined) {
          const newLogin = validateLogin(body.login);
          if (!newLogin) {
            return sendJson(res, 400, { error: 'Логин должен содержать от 2 до 64 символов (русские/латинские буквы, цифры, пробел, . _ -).' });
          }
          const existing = store.findUserByLogin(newLogin);
          if (existing && existing.id !== auth.user.id) {
            return sendJson(res, 400, { error: 'Этот логин уже занят другим пользователем.' });
          }
          auth.user.login = newLogin;
        }
        if (body.displayName !== undefined) {
          auth.user.displayName = String(body.displayName || '').trim().slice(0, 100) || auth.user.login;
        }
        auth.user.updatedAt = Date.now();
        store.saveUsers();
        store.logEvent({
          action: 'owner.profile.updated',
          actor: auth.user,
          target: auth.user.login,
          ip,
          userAgent
        });
        return sendJson(res, 200, { ok: true, user: sanitizeUser(auth.user) });
      }

      // Users management: GET /api/users, POST /api/users, PATCH /api/users/:id, DELETE /api/users/:id
      if (pathname === '/api/users' || pathname.startsWith('/api/users/')) {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        const targetId = pathname.split('/')[3] || null;

        // List users: OWNER or user with users.view permission
        if (method === 'GET' && !targetId) {
          if (auth.user.role !== 'OWNER' && !hasPermission(auth.user, 'users.view')) {
            return sendJson(res, 403, { error: 'Доступ к списку пользователей разрешён только OWNER или уполномоченным администраторам.' });
          }
          const activeSessions = store.getSessions();
          const list = store.getUsers().map(u => ({
            ...sanitizeUser(u),
            activeSessionsCount: activeSessions.filter(s => s.userId === u.id).length
          }));
          return sendJson(res, 200, { users: list, availablePermissions: ALL_PERMISSIONS, roleDefaults: DEFAULT_ROLE_PERMISSIONS });
        }

        // All mutating operations on users require OWNER (or specifically delegated ADMIN for non-admin/non-owner users if allowed,
        // but per Requirements 1 & 2:
        // "OWNER может создавать, редактировать, блокировать и удалять пользователей. Назначать роли и права доступа. Управлять администраторами и их полномочиями."
        // "Ни один другой пользователь, включая администраторов, не может удалить, заблокировать или изменить права OWNER.")
        if (auth.user.role !== 'OWNER') {
          store.logEvent({
            action: 'users.manage.denied',
            actor: auth.user,
            target: targetId,
            ip,
            userAgent,
            status: 'denied',
            details: { method, pathname }
          });
          return sendJson(res, 403, { error: 'Управление пользователями, ролями и администраторами доступно только главной учётной записи OWNER.' });
        }

        // Create user (POST /api/users)
        if (method === 'POST' && !targetId) {
          const body = await readBody(req);
          if (body.role === 'OWNER') {
            store.logEvent({
              action: 'users.create.owner_duplicate_denied',
              actor: auth.user,
              ip,
              userAgent,
              status: 'denied'
            });
            return sendJson(res, 403, { error: 'В системе может быть только один OWNER. Создание второго OWNER запрещено.' });
          }
          const login = validateLogin(body.login);
          if (!login) {
            return sendJson(res, 400, { error: 'Логин должен содержать от 2 до 64 символов (русские/латинские буквы, цифры, пробел, . _ -).' });
          }
          if (store.findUserByLogin(login)) {
            return sendJson(res, 400, { error: 'Пользователь с таким логином уже существует.' });
          }
          if (!validatePassword(body.password)) {
            return sendJson(res, 400, { error: 'Пароль должен содержать от 4 до 128 символов.' });
          }
          const role = ['ADMIN', 'EDITOR', 'OPERATOR'].includes(body.role) ? body.role : 'OPERATOR';
          const permissions = Array.isArray(body.permissions)
            ? body.permissions.filter(p => ALL_PERMISSIONS.includes(p))
            : [...(DEFAULT_ROLE_PERMISSIONS[role] || [])];
          const now = Date.now();
          const newUser = {
            id: 'usr_' + crypto.randomUUID(),
            login,
            displayName: String(body.displayName || login).trim().slice(0, 100) || login,
            role,
            passwordHash: hashPassword(body.password),
            blocked: Boolean(body.blocked),
            permissions,
            createdAt: now,
            updatedAt: now,
            lastLoginAt: null
          };
          store.addUser(newUser);
          store.logEvent({
            action: 'users.create',
            actor: auth.user,
            target: newUser.login,
            ip,
            userAgent,
            details: { userId: newUser.id, role: newUser.role, permissions: newUser.permissions, blocked: newUser.blocked }
          });
          return sendJson(res, 201, { user: sanitizeUser(newUser) });
        }

        // Modify user (PATCH /api/users/:id)
        if (method === 'PATCH' && targetId) {
          const targetUser = store.findUserById(targetId);
          if (!targetUser) {
            return sendJson(res, 404, { error: 'Пользователь не найден.' });
          }
          const body = await readBody(req);

          if (targetUser.role === 'OWNER') {
            // Protect OWNER even from accidental self-demotion/self-block via user API
            if (body.blocked === true || (body.role !== undefined && body.role !== 'OWNER') || body.permissions !== undefined) {
              store.logEvent({
                action: 'owner.protection.triggered',
                actor: auth.user,
                target: targetUser.login,
                ip,
                userAgent,
                status: 'denied',
                details: { attemptedChanges: Object.keys(body) }
              });
              return sendJson(res, 403, { error: 'Невозможно заблокировать, понизить роль или ограничить права главной учётной записи OWNER.' });
            }
          }

          if (body.role === 'OWNER' && targetUser.role !== 'OWNER') {
            store.logEvent({
              action: 'owner.promotion.denied',
              actor: auth.user,
              target: targetUser.login,
              ip,
              userAgent,
              status: 'denied'
            });
            return sendJson(res, 403, { error: 'В системе может быть только один OWNER. Назначение роли OWNER другому пользователю запрещено.' });
          }

          const changes = {};
          if (body.login !== undefined && body.login !== targetUser.login) {
            const newLogin = validateLogin(body.login);
            if (!newLogin) {
              return sendJson(res, 400, { error: 'Некорректный формат логина (2–64 символа: русские/латинские буквы, цифры, пробел, . _ -).' });
            }
            const existing = store.findUserByLogin(newLogin);
            if (existing && existing.id !== targetUser.id) {
              return sendJson(res, 400, { error: 'Этот логин уже используется другим пользователем.' });
            }
            changes.login = { from: targetUser.login, to: newLogin };
            targetUser.login = newLogin;
          }

          if (body.displayName !== undefined) {
            const dn = String(body.displayName || '').trim().slice(0, 100) || targetUser.login;
            changes.displayName = dn;
            targetUser.displayName = dn;
          }

          if (body.role !== undefined && targetUser.role !== 'OWNER') {
            if (!['ADMIN', 'EDITOR', 'OPERATOR'].includes(body.role)) {
              return sendJson(res, 400, { error: 'Недопустимая роль пользователя.' });
            }
            changes.role = { from: targetUser.role, to: body.role };
            targetUser.role = body.role;
          }

          if (body.permissions !== undefined && targetUser.role !== 'OWNER') {
            if (!Array.isArray(body.permissions)) {
              return sendJson(res, 400, { error: 'Список прав должен быть массивом.' });
            }
            const cleanPerms = [...new Set(body.permissions.filter(p => ALL_PERMISSIONS.includes(p)))];
            changes.permissions = cleanPerms;
            targetUser.permissions = cleanPerms;
          }

          if (body.blocked !== undefined && targetUser.role !== 'OWNER') {
            const nextBlocked = Boolean(body.blocked);
            if (targetUser.blocked !== nextBlocked) {
              changes.blocked = nextBlocked;
              targetUser.blocked = nextBlocked;
              if (nextBlocked) {
                store.revokeUserSessions(targetUser.id);
              }
            }
          }

          if (body.password !== undefined && body.password !== '') {
            if (!validatePassword(body.password)) {
              return sendJson(res, 400, { error: 'Пароль должен содержать от 4 до 128 символов.' });
            }
            targetUser.passwordHash = hashPassword(body.password);
            changes.passwordReset = true;
            if (targetUser.id !== auth.user.id) {
              store.revokeUserSessions(targetUser.id);
            }
          }

          targetUser.updatedAt = Date.now();
          store.saveUsers();
          store.logEvent({
            action: 'users.update',
            actor: auth.user,
            target: targetUser.login,
            ip,
            userAgent,
            details: { userId: targetUser.id, changes }
          });
          return sendJson(res, 200, { user: sanitizeUser(targetUser) });
        }

        // Delete user (DELETE /api/users/:id)
        if (method === 'DELETE' && targetId) {
          const targetUser = store.findUserById(targetId);
          if (!targetUser) {
            return sendJson(res, 404, { error: 'Пользователь не найден.' });
          }
          if (targetUser.role === 'OWNER') {
            store.logEvent({
              action: 'owner.delete.denied',
              actor: auth.user,
              target: targetUser.login,
              ip,
              userAgent,
              status: 'denied'
            });
            return sendJson(res, 403, { error: 'Невозможно удалить главную учётную запись OWNER.' });
          }
          store.removeUser(targetId);
          store.logEvent({
            action: 'users.delete',
            actor: auth.user,
            target: targetUser.login,
            ip,
            userAgent,
            details: { deletedUserId: targetUser.id, deletedRole: targetUser.role }
          });
          return sendJson(res, 200, { ok: true });
        }
      }

      // Sessions management: GET /api/sessions, DELETE /api/sessions/:id, POST /api/sessions/revoke-user
      if (pathname === '/api/sessions' || pathname.startsWith('/api/sessions/')) {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        if (auth.user.role !== 'OWNER') {
          store.logEvent({ action: 'sessions.access.denied', actor: auth.user, ip, userAgent, status: 'denied' });
          return sendJson(res, 403, { error: 'Управление сессиями доступно только главной учётной записи OWNER.' });
        }

        const sub = pathname.split('/')[3] || null;
        if (method === 'GET' && !sub) {
          const list = store.getSessions().map(s => {
            const u = store.findUserById(s.userId);
            return {
              id: s.id,
              userId: s.userId,
              userLogin: u?.login || s.userLogin,
              displayName: u?.displayName || s.userLogin,
              userRole: u?.role || s.userRole,
              ip: s.ip,
              userAgent: s.userAgent,
              createdAt: s.createdAt,
              lastActiveAt: s.lastActiveAt,
              expiresAt: s.expiresAt,
              current: s.id === auth.session.id
            };
          }).sort((a, b) => b.lastActiveAt - a.lastActiveAt);
          return sendJson(res, 200, { sessions: list });
        }

        if (method === 'POST' && sub === 'revoke-user') {
          const body = await readBody(req);
          const userId = body.userId;
          const targetUser = store.findUserById(userId);
          if (!targetUser) return sendJson(res, 404, { error: 'Пользователь не найден.' });
          const exceptId = userId === auth.user.id ? auth.session.id : null;
          const count = store.revokeUserSessions(userId, exceptId);
          store.logEvent({
            action: 'sessions.revoke_user',
            actor: auth.user,
            target: targetUser.login,
            ip,
            userAgent,
            details: { userId, revokedCount: count }
          });
          return sendJson(res, 200, { ok: true, revokedCount: count });
        }

        if (method === 'DELETE' && sub) {
          const removed = store.revokeSessionById(sub);
          if (!removed) return sendJson(res, 404, { error: 'Сессия не найдена или уже завершена.' });
          store.logEvent({
            action: 'sessions.revoke',
            actor: auth.user,
            target: removed.userLogin,
            ip,
            userAgent,
            details: { sessionId: removed.id, targetUserId: removed.userId }
          });
          return sendJson(res, 200, { ok: true });
        }
      }

      // Audit log: GET /api/audit
      if (pathname === '/api/audit' && method === 'GET') {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        if (auth.user.role !== 'OWNER' && !hasPermission(auth.user, 'audit.view')) {
          store.logEvent({ action: 'audit.access.denied', actor: auth.user, ip, userAgent, status: 'denied' });
          return sendJson(res, 403, { error: 'Журнал действий доступен только главной учётной записи OWNER.' });
        }
        const limit = Math.min(500, Math.max(10, Number(url.searchParams.get('limit')) || 200));
        const filterUser = (url.searchParams.get('user') || '').trim().toLowerCase();
        const filterAction = (url.searchParams.get('action') || '').trim().toLowerCase();

        let entries = [...store.getAudit()].reverse();
        if (filterUser) {
          entries = entries.filter(e =>
            (e.actorLogin || '').toLowerCase().includes(filterUser) ||
            (e.target || '').toLowerCase().includes(filterUser)
          );
        }
        if (filterAction) {
          entries = entries.filter(e => (e.action || '').toLowerCase().includes(filterAction));
        }
        return sendJson(res, 200, { events: entries.slice(0, limit), total: entries.length });
      }

      return sendJson(res, 404, { error: 'Маршрут API не найден.' });
    } catch (err) {
      const status = err.status || 500;
      return sendJson(res, status, { error: err.message || 'Внутренняя ошибка сервера.' });
    }
  });

  return { server, store };
}

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || '127.0.0.1';
  const { server, store } = createAppServer();
  server.listen(port, host, () => {
    const owner = store.getOwner();
    console.log(`============================================================`);
    console.log(`BAUER Навигатор разговора запущен: http://${host}:${port}`);
    console.log(`Статус главной записи OWNER: ${owner ? `активна (${owner.login})` : 'ожидает первичной настройки при первом входе'}`);
    console.log(`Хранилище данных: ${DEFAULT_DATA_DIR}`);
    console.log(`============================================================`);
  });
}

module.exports = {
  createAppServer,
  ALL_PERMISSIONS,
  DEFAULT_ROLE_PERMISSIONS,
  hashPassword,
  verifyPassword
};
