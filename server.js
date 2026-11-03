'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
let vercelBlob = null;
try {
  vercelBlob = require('@vercel/blob');
} catch {
  vercelBlob = null;
}

const ROOT_DIR = __dirname;
const INDEX_PATH = path.join(ROOT_DIR, 'index.html');
const DEFAULT_DATA_DIR = process.env.BAUER_DATA_DIR || (process.env.VERCEL ? path.join(os.tmpdir(), 'bauer-data') : path.join(ROOT_DIR, 'data'));

const SESSION_COOKIE = 'bauer_sid';
const CSRF_COOKIE = 'bauer_csrf';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_BODY_BYTES = 12 * 1024 * 1024; // 12 MB (for base64 gift photos in layouts/content)

const ALL_PERMISSIONS = [
  'content.edit',
  'layouts.manage',
  'layouts.delete',
  'gifts.manage',
  'addresses.manage',
  'settings.manage',
  'users.view',
  'users.manage',
  'sessions.manage',
  'audit.view'
];

const DEFAULT_ROLE_PERMISSIONS = {
  OWNER: [...ALL_PERMISSIONS, 'admins.manage', 'owner.full'],
  ADMIN: [...ALL_PERMISSIONS],
  EDITOR: ['content.edit', 'layouts.manage', 'layouts.delete', 'gifts.manage', 'addresses.manage', 'settings.manage'],
  HEAD: ['content.edit', 'layouts.manage', 'users.view', 'users.manage', 'sessions.manage'],
  OPERATOR: ['settings.manage']
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
      const activeLayouts = layoutsData.filter(l => l && l.name && !/^Перед изменением/i.test(l.name));
      seed.layouts = activeLayouts;
      for (const l of activeLayouts) {
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
  try {
    fs.mkdirSync(dataDir, { recursive: true });
  } catch (err) {
    console.warn(`[server.js] Could not create dataDir "${dataDir}": ${err.message}. Using fallback in os.tmpdir()`);
    dataDir = path.join(os.tmpdir(), 'bauer-data');
    try { fs.mkdirSync(dataDir, { recursive: true }); } catch {}
  }
  const files = {
    users: path.join(dataDir, 'users.json'),
    sessions: path.join(dataDir, 'sessions.json'),
    audit: path.join(dataDir, 'audit.json'),
    appData: path.join(dataDir, 'app-data.json'),
    sharedThemes: path.join(dataDir, 'shared-themes.json')
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
    try {
      fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { encoding: 'utf8' });
      fs.renameSync(tmp, filePath);
    } catch (err) {
      try {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), { encoding: 'utf8' });
      } catch (fallbackErr) {
        console.error('writeJson error:', filePath, fallbackErr.message);
      }
      try { if (fs.existsSync(tmp)) fs.unlinkSync(tmp); } catch {}
    }
  }

  let users = readJson(files.users, []);
  let sessions = readJson(files.sessions, []);
  let audit = readJson(files.audit, []);
  let appData = readJson(files.appData, null);
  let sharedThemes = readJson(files.sharedThemes, []);
  function saveSharedThemes() {
    dirtySharedThemes = true;
    writeJsonAtomic(files.sharedThemes, sharedThemes);
  }
  let dirtyAuth = false;
  let dirtyAppData = false;
  let dirtySharedThemes = false;
  let blobAppDataLoaded = false;

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

  if (appData && Array.isArray(appData.layouts)) {
    const prevCount = appData.layouts.length;
    appData.layouts = appData.layouts.filter(l => l && l.name && !/^Перед изменением/i.test(l.name));
    if (appData.layouts.length !== prevCount) {
      writeJsonAtomic(files.appData, appData);
    }
  }

  function enforceOwnerInvariants() {
    if (seedDefaultOwner && !users.some(u => u.role === 'OWNER')) {
      users.unshift(structuredClone(DEFAULT_OWNER_USER));
      writeJsonAtomic(files.users, users);
    }
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
    let migrated = false;
    users.forEach(u => {
      if (u.role === 'ADMIN' && !u.permissionsMigratedV2) {
        u.permissions = [...new Set([...(u.permissions || []), ...DEFAULT_ROLE_PERMISSIONS.ADMIN])];
        u.permissionsMigratedV2 = true;
        migrated = true;
      } else if (u.role === 'EDITOR' && !u.permissionsMigratedV2) {
        if (Array.isArray(u.permissions) && u.permissions.includes('layouts.manage') && !u.permissions.includes('layouts.delete')) {
          u.permissions.push('layouts.delete');
        }
        u.permissionsMigratedV2 = true;
        migrated = true;
      } else if (u.role === 'OPERATOR' && !u.permissionsMigratedV3) {
        if (!Array.isArray(u.permissions) || !u.permissions.includes('settings.manage')) {
          u.permissions = [...new Set([...(u.permissions || []), 'settings.manage'])];
        }
        u.permissionsMigratedV3 = true;
        migrated = true;
      }
    });
    if (migrated) {
      writeJsonAtomic(files.users, users);
    }
  }
  enforceOwnerInvariants();

  function saveUsers() {
    const ownerCount = users.filter(u => u.role === 'OWNER').length;
    if (ownerCount > 1) {
      throw new Error('Нарушение инварианта: в системе может быть только один OWNER.');
    }
    writeJsonAtomic(files.users, users);
    dirtyAuth = true;
  }

  function saveSessions() {
    writeJsonAtomic(files.sessions, sessions);
    dirtyAuth = true;
  }

  function saveAudit() {
    if (audit.length > 2500) {
      audit = audit.slice(-2500);
    }
    writeJsonAtomic(files.audit, audit);
    dirtyAuth = true;
  }

  function saveAppData() {
    writeJsonAtomic(files.appData, appData);
    dirtyAppData = true;
  }

  let lastBlobSyncAt = 0;
  async function syncFromBlob({ needAppData = false, force = false } = {}) {
    if (!process.env.BLOB_READ_WRITE_TOKEN || !vercelBlob) return;
    const now = Date.now();
    if (!force && (now - lastBlobSyncAt < 30000)) return;
    lastBlobSyncAt = now;
    try {
      const authRes = await vercelBlob.get('bauer-state/auth.json', {
        access: 'private',
        useCache: false
      });
      if (authRes && authRes.statusCode === 200 && authRes.stream) {
        const remoteAuth = await new Response(authRes.stream).json();
        if (remoteAuth && typeof remoteAuth === 'object') {
          if (Array.isArray(remoteAuth.users)) users = remoteAuth.users;
          if (Array.isArray(remoteAuth.sessions)) sessions = remoteAuth.sessions;
          if (Array.isArray(remoteAuth.audit)) audit = remoteAuth.audit;
          enforceOwnerInvariants();
        }
      } else if (!authRes) {
        dirtyAuth = true;
      }
    } catch (err) {
      console.warn('Blob auth sync warning:', err.message);
    }

    try {
        const thRes = await vercelBlob.get('bauer-state/shared-themes.json', { access: 'private', useCache: false });
        if (thRes && thRes.statusCode === 200 && thRes.stream) {
          const remoteThemes = await new Response(thRes.stream).json();
          if (Array.isArray(remoteThemes)) sharedThemes = remoteThemes;
        }
      } catch (err) {}

    if (needAppData && !blobAppDataLoaded) {
      try {
        const appRes = await vercelBlob.get('bauer-state/app-data.json', {
          access: 'private',
          useCache: false
        });
        if (appRes && appRes.statusCode === 200 && appRes.stream) {
          const remoteApp = await new Response(appRes.stream).json();
          if (remoteApp && typeof remoteApp === 'object') {
            appData = remoteApp;
            if (Array.isArray(appData?.layouts)) {
              const prevCount = appData.layouts.length;
              appData.layouts = appData.layouts.filter(l => l && l.name && !/^Перед изменением/i.test(l.name));
              if (appData.layouts.length !== prevCount) {
                dirtyAppData = true;
              }
            }
          }
        }
        blobAppDataLoaded = true;
      } catch (err) {
        console.warn('Blob appData sync warning:', err.message);
      }
    }
  }

  async function flushToBlob() {
    if (!process.env.BLOB_READ_WRITE_TOKEN || !vercelBlob) return;
    if (dirtyAuth) {
      dirtyAuth = false;
      try {
        await vercelBlob.put('bauer-state/auth.json', JSON.stringify({ users, sessions, audit }), {
          access: 'private',
          addRandomSuffix: false,
          allowOverwrite: true,
          contentType: 'application/json'
        });
      } catch (err) {
        console.error('Blob auth write error:', err.message);
      }
    }
    if (dirtySharedThemes) {
      dirtySharedThemes = false;
      try {
        await vercelBlob.put('bauer-state/shared-themes.json', JSON.stringify(sharedThemes), {
          access: 'private',
          addRandomSuffix: false,
          allowOverwrite: true,
          contentType: 'application/json'
        });
      } catch (err) {
        console.error('Blob sharedThemes write error:', err.message);
      }
    }
    if (dirtyAppData) {
      dirtyAppData = false;
      try {
        await vercelBlob.put('bauer-state/app-data.json', JSON.stringify(appData), {
          access: 'private',
          addRandomSuffix: false,
          allowOverwrite: true,
          contentType: 'application/json'
        });
      } catch (err) {
        console.error('Blob appData write error:', err.message);
      }
    }
  }

  function logEvent({ action, actor, target = null, ip = '', userAgent = '', details = {}, status = 'success' }) {
    const entry = {
      id: 'ev_' + crypto.randomUUID(),
      timestamp: Date.now(),
      action,
      status,
      actorId: actor?.id || null,
      actorLogin: actor?.login || (typeof actor === 'string' ? actor : 'anonymous'),
      actorName: actor?.displayName || actor?.login || (typeof actor === 'string' ? actor : 'anonymous'),
      actorRole: actor?.role || null,
      actorManagerId: actor?.managerId || null,
      target,
      ip: String(ip || '').slice(0, 100),
      userAgent: String(userAgent || '').slice(0, 250),
      details: { ...details, clicks: Math.max(1, Number(details?.clicks || details?.count || 1)) }
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
      users.forEach(x => {
        if (x.managerId === id) x.managerId = null;
      });
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
      const interval = process.env.BLOB_READ_WRITE_TOKEN ? 10 * 60 * 1000 : 30000;
      if (now - session.lastActiveAt > interval) {
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
    saveAppData,
    getSharedThemes: () => sharedThemes,
    addSharedTheme: (t) => { sharedThemes.push(t); saveSharedThemes(); return t; },
    removeSharedTheme: (id) => {
      const before = sharedThemes.length;
      sharedThemes = sharedThemes.filter(x => x.id !== id);
      if (sharedThemes.length !== before) saveSharedThemes();
      return sharedThemes.length !== before;
    },
    updateSharedTheme: (id, patch) => {
      const item = sharedThemes.find(x => x.id === id);
      if (item) { Object.assign(item, patch); saveSharedThemes(); }
      return item;
    },
    syncFromBlob,
    flushToBlob
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
    managerId: u.managerId || null,
    departmentScripts: Array.isArray(u.departmentScripts) ? u.departmentScripts : [],
    mustChangePassword: Boolean(u.mustChangePassword),
    blocked: isOwner ? false : Boolean(u.blocked),
    permissions: isOwner ? [...DEFAULT_ROLE_PERMISSIONS.OWNER] : (Array.isArray(u.permissions) ? u.permissions : []),
    theme: u.theme || null,
    customThemes: Array.isArray(u.customThemes) ? u.customThemes : [],
    createdAt: u.createdAt || 0,
    updatedAt: u.updatedAt || 0,
    lastLoginAt: u.lastLoginAt || null,
    recoveryCodesRemaining: isOwner && Array.isArray(u.recoveryCodes) ? u.recoveryCodes.filter(c => !c.used).length : undefined
  };
}

function isScriptTextUnchanged(originalData, nextData) {
  if (!originalData || !nextData) return false;
  const origStages = Array.isArray(originalData.stages) ? originalData.stages : [];
  const nextStages = Array.isArray(nextData.stages) ? nextData.stages : [];
  if (origStages.length !== nextStages.length) return false;
  for (let i = 0; i < origStages.length; i++) {
    const o = origStages[i], n = nextStages[i];
    if (o.id !== n.id) return false;
    if (String(o.title || '') !== String(n.title || '')) return false;
    if (String(o.tip || '') !== String(n.tip || '')) return false;
    const oLines = Array.isArray(o.lines) ? o.lines : [];
    const nLines = Array.isArray(n.lines) ? n.lines : [];
    if (oLines.length !== nLines.length) return false;
    for (let j = 0; j < oLines.length; j++) {
      if (String(oLines[j] || '') !== String(nLines[j] || '')) return false;
    }
  }
  const origObs = Array.isArray(originalData.objections) ? originalData.objections : [];
  const nextObs = Array.isArray(nextData.objections) ? nextData.objections : [];
  if (origObs.length !== nextObs.length) return false;
  for (let i = 0; i < origObs.length; i++) {
    const o = origObs[i], n = nextObs[i];
    if (String(o.title || '') !== String(n.title || '')) return false;
    if (String(o.text || '') !== String(n.text || '')) return false;
  }
  return true;
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

  async function sendJson(res, status, payload, extraHeaders = {}) {
    await store.flushToBlob();
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

  // Brute-force rate limiter in memory (tracks failed attempts)
  const loginAttempts = new Map(); // key -> { count, resetAt }

  function checkRateLimit(key, maxAttempts = 30, windowMs = 5 * 60 * 1000) {
    const now = Date.now();
    const rec = loginAttempts.get(key);
    if (!rec || now > rec.resetAt) {
      return true;
    }
    return rec.count < maxAttempts;
  }

  function recordFailedLogin(key, windowMs = 5 * 60 * 1000) {
    const now = Date.now();
    const rec = loginAttempts.get(key);
    if (!rec || now > rec.resetAt) {
      loginAttempts.set(key, { count: 1, resetAt: now + windowMs });
    } else {
      rec.count += 1;
    }
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
        if (pathname === '/health' || pathname === '/healthz' || pathname === '/ping' || pathname === '/api/health') {
          res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end('ok');
          return;
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

      const needAppData = ['/api/content', '/api/scripts', '/api/giftbase', '/api/addresses', '/api/layouts', '/api/layouts-order'].some(
        p => pathname === p || pathname.startsWith(p + '/')
      );
      await store.syncFromBlob({ needAppData });

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
        if (auth.user.mustChangePassword && pathname !== '/api/auth/change-password' && pathname !== '/api/admin/logout') {
          return sendJson(res, 403, {
            error: 'Вам необходимо сменить временный пароль на собственный перед выполнением действий в системе.',
            mustChangePassword: true
          });
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

        if (!checkRateLimit(rateKey, 30, 5 * 60 * 1000)) {
          store.logEvent({
            action: 'auth.login.rate_limited',
            actor: login || 'anonymous',
            ip,
            userAgent,
            status: 'failed',
            details: { login }
          });
          return sendJson(res, 429, { error: 'Слишком много неверных попыток входа. Подождите 5 минут и попробуйте снова.' });
        }

        if (!store.getOwner()) {
          return sendJson(res, 400, { error: 'Система ещё не инициализирована. Создайте учётную запись OWNER.' });
        }

        const user = store.findUserByLogin(login);
        if (!user || !verifyPassword(password, user.passwordHash)) {
          recordFailedLogin(rateKey, 5 * 60 * 1000);
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

      // 4.1. POST /api/auth/change-password (Employee sets their permanent password after first login)
      if (pathname === '/api/auth/change-password' && method === 'POST') {
        if (!auth) {
          return sendJson(res, 401, { error: 'Требуется авторизация.' });
        }
        const body = await readBody(req);
        const newPassword = String(body.newPassword || '');
        if (!validatePassword(newPassword)) {
          return sendJson(res, 400, { error: 'Новый пароль должен содержать от 4 до 128 символов.' });
        }
        const wasTemp = Boolean(auth.user.mustChangePassword);
        auth.user.passwordHash = hashPassword(newPassword);
        auth.user.mustChangePassword = false;
        auth.user.updatedAt = Date.now();
        store.saveUsers();
        store.logEvent({
          action: wasTemp ? 'auth.password.change_initial' : 'auth.password.change',
          actor: auth.user,
          target: auth.user.login,
          ip,
          userAgent,
          details: { wasTemp }
        });
        return sendJson(res, 200, {
          ok: true,
          user: sanitizeUser(auth.user)
        });
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
          const hasContentEdit = hasPermission(auth.user, 'content.edit');
          const hasSettingsManage = hasPermission(auth.user, 'settings.manage');
          if (!hasContentEdit && !hasSettingsManage) {
            store.logEvent({ action: 'content.update.denied', actor: auth.user, ip, userAgent, status: 'denied' });
            return sendJson(res, 403, { error: 'Недостаточно прав для публикации изменений скрипта.' });
          }
          const body = await readBody(req);
          if (!body.data || typeof body.data !== 'object') {
            return sendJson(res, 400, { error: 'Некорректные данные скрипта.' });
          }
          // Strict text immutability check for operators (users without content.edit)
          if (!hasContentEdit) {
            if (!isScriptTextUnchanged(appData.content?.data, body.data)) {
              store.logEvent({ action: 'content.text_change_blocked', actor: auth.user, ip, userAgent, status: 'denied' });
              return sendJson(res, 403, { error: 'Менеджер обзвона не имеет права менять текст скрипта. Доступно только изменение оформления, цветов и шрифтов.' });
            }
          }
          const currentSettings = appData.content?.data?.settings;
          if (
            currentSettings &&
            body.data.settings &&
            JSON.stringify(body.data.settings) !== JSON.stringify(currentSettings) &&
            !hasSettingsManage
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
            details: { stagesCount: Array.isArray(body.data.stages) ? body.data.stages.length : 0, stylingOnly: !hasContentEdit }
          });
          return sendJson(res, 200, { updatedAt });
        }
      }

      if (pathname === '/api/scripts' && method === 'GET') {
        const allLayouts = (appData.layouts || []).filter(l => l && l.name && !/^Перед изменением/i.test(l.name));
        let resultLayouts = allLayouts;
        let deptScripts = [];
        if (auth && auth.user) {
          let mgr = null;
          const allUsers = store.getUsers();
          if (auth.user.role === 'OPERATOR') {
            if (auth.user.managerId) {
              mgr = allUsers.find(u => u.id === auth.user.managerId);
            }
          } else if (auth.user.role === 'HEAD' || auth.user.role === 'OWNER') {
            mgr = auth.user;
          }
          if (mgr && Array.isArray(mgr.departmentScripts) && mgr.departmentScripts.length > 0) {
            deptScripts = mgr.departmentScripts.map(String);
            if (auth.user.role === 'OPERATOR') {
              const deptSet = new Set(deptScripts);
              const filtered = allLayouts.filter(l => deptSet.has(String(l.id)));
              if (filtered.length > 0) {
                resultLayouts = filtered;
              }
            }
          }
        }
        return sendJson(res, 200, {
          layouts: resultLayouts,
          allLayouts,
          departmentScripts: deptScripts
        });
      }


      // Shared Themes: GET /api/themes/shared, POST /api/themes/shared, DELETE /api/themes/shared
      if (pathname === '/api/themes/shared') {
        if (!auth && method !== 'GET') return sendJson(res, 401, { error: 'Требуется авторизация.' });
        if (!auth && method === 'GET') return sendJson(res, 200, { ok: true, sharedThemes: [] });
        const allUsers = store.getUsers();
        const user = auth.user;
        const isOwner = user.role === 'OWNER';
        const isAdmin = user.role === 'ADMIN';
        const isHead = user.role === 'HEAD';

        if (method === 'GET') {
          const list = store.getSharedThemes();
          const visible = list.filter(t => {
            if (t.senderId === user.id) return true;
            if (t.targetUserId === user.id) return true;
            if (t.shareAll) {
              if (isOwner || isAdmin) return true;
              const sender = allUsers.find(u => u.id === t.senderId);
              if (!sender) return true;
              if (sender.role === 'OWNER' || sender.role === 'ADMIN') return true;
              if (sender.role === 'HEAD' && user.managerId === sender.id) return true;
              if (user.managerId && sender.managerId === user.managerId) return true;
              if (isHead && sender.managerId === user.id) return true;
              return false;
            }
            return false;
          });
          return sendJson(res, 200, { sharedThemes: visible });
        }

        if (method === 'POST') {
          const body = await readBody(req);
          if (!body || !body.theme || !body.theme.name) {
            return sendJson(res, 400, { error: 'Необходимо передать данные темы и название.' });
          }
          const item = {
            id: 'sh_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
            name: String(body.theme.name).trim().slice(0, 60),
            desc: String(body.theme.desc || '').slice(0, 120),
            themeData: body.theme,
            senderId: user.id,
            senderLogin: user.login,
            senderName: user.displayName || user.login,
            targetUserId: body.shareAll ? null : (body.targetUserId || null),
            targetUserName: body.targetUserName || null,
            shareAll: !!body.shareAll,
            createdAt: Date.now()
          };
          store.addSharedTheme(item);
          return sendJson(res, 201, { ok: true, theme: item });
        }

        if (method === 'DELETE') {
          const id = url.searchParams.get('id');
          if (!id) return sendJson(res, 400, { error: 'Не указан идентификатор темы.' });
          const list = store.getSharedThemes();
          const item = list.find(x => x.id === id);
          if (!item) return sendJson(res, 404, { error: 'Тема не найдена.' });
          if (item.senderId !== user.id && !isOwner && !isAdmin && item.targetUserId !== user.id) {
            return sendJson(res, 403, { error: 'Нет прав на удаление этой темы.' });
          }
          store.removeSharedTheme(id);
          return sendJson(res, 200, { ok: true, deleted: id });
        }

        return sendJson(res, 405, { error: 'Метод не поддерживается.' });
      }

      // Department colleagues for theme sharing & collaboration: GET /api/department/colleagues
      if (pathname === '/api/department/colleagues' && method === 'GET') {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        const user = auth.user;
        const allUsers = store.getUsers();
        let colleagues = [];
        if (user.role === 'OWNER' || user.role === 'ADMIN') {
          colleagues = allUsers.filter(u => u.id !== user.id && !u.blocked);
        } else if (user.role === 'HEAD') {
          colleagues = allUsers.filter(u => u.id !== user.id && !u.blocked && (u.managerId === user.id || u.role === 'HEAD' || u.role === 'OWNER'));
        } else {
          // Operator: their manager and peer operators under the same manager
          const myManagerId = user.managerId || null;
          colleagues = allUsers.filter(u => {
            if (u.id === user.id || u.blocked) return false;
            if (myManagerId) {
              return u.id === myManagerId || u.managerId === myManagerId;
            }
            return u.role === 'HEAD' || u.role === 'OWNER' || !u.managerId;
          });
        }
        return sendJson(res, 200, {
          colleagues: colleagues.map(u => ({
            id: u.id,
            login: u.login,
            displayName: u.displayName || u.login,
            role: u.role
          }))
        });
      }

      // Department scripts: GET /api/department/scripts, PUT /api/department/scripts
      if (pathname === '/api/department/scripts') {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        const allUsers = store.getUsers();
        const allLayouts = (appData.layouts || []).filter(l => l && l.name && !/^Перед изменением/i.test(l.name));
        const isOwner = auth.user.role === 'OWNER';
        const isHead = auth.user.role === 'HEAD';
        const isAdmin = auth.user.role === 'ADMIN';

        if (method === 'GET') {
          let targetHead = null;
          const requestedHeadId = url.searchParams.get('headId');
          if (requestedHeadId && (isOwner || isAdmin)) {
            targetHead = allUsers.find(u => u.id === requestedHeadId && (u.role === 'HEAD' || u.role === 'OWNER'));
          } else if (isHead || isOwner) {
            targetHead = auth.user;
          } else if (isAdmin) {
            targetHead = allUsers.find(u => u.role === 'OWNER') || allUsers.find(u => u.role === 'HEAD') || null;
          } else if (auth.user.role === 'OPERATOR' && auth.user.managerId) {
            targetHead = allUsers.find(u => u.id === auth.user.managerId && (u.role === 'HEAD' || u.role === 'OWNER'));
          }
          const scriptIds = Array.isArray(targetHead?.departmentScripts) ? [...new Set(targetHead.departmentScripts.map(String))] : [];
          return sendJson(res, 200, {
            headId: targetHead?.id || null,
            headLogin: targetHead?.login || null,
            headDisplayName: targetHead?.displayName || targetHead?.login || null,
            scriptIds,
            layouts: allLayouts.map(l => ({ id: l.id, name: l.name, savedAt: l.savedAt, stagesCount: l.data?.stages?.length || 0 }))
          });
        }

        if (method === 'PUT') {
          if (!isOwner && !isHead && !isAdmin) {
            return sendJson(res, 403, { error: 'Настройка скриптов отдела доступна только руководителю отдела и руководству.' });
          }
          const body = await readBody(req);
          if (!Array.isArray(body.scriptIds)) {
            return sendJson(res, 400, { error: 'Параметр scriptIds должен быть массивом идентификаторов макетов.' });
          }
          let targetHead = null;
          if (body.headId && (isOwner || isAdmin)) {
            targetHead = allUsers.find(u => u.id === body.headId && (u.role === 'HEAD' || u.role === 'OWNER'));
            if (!targetHead) {
              return sendJson(res, 404, { error: 'Указанный руководитель отдела не найден.' });
            }
          } else if (isHead || isOwner) {
            targetHead = auth.user;
          } else if (isAdmin) {
            targetHead = allUsers.find(u => u.role === 'OWNER') || allUsers.find(u => u.role === 'HEAD') || null;
          }
          if (!targetHead) {
            return sendJson(res, 400, { error: 'Не указан руководитель отдела.' });
          }
          const cleanIds = [...new Set(body.scriptIds.map(String).filter(Boolean))];
          targetHead.departmentScripts = cleanIds;
          targetHead.updatedAt = Date.now();
          store.saveUsers();
          store.logEvent({
            action: 'department.scripts.update',
            actor: auth.user,
            target: targetHead.login,
            ip,
            userAgent,
            details: { headId: targetHead.id, scriptIds: cleanIds, count: cleanIds.length }
          });
          return sendJson(res, 200, { ok: true, headId: targetHead.id, scriptIds: cleanIds });
        }
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
          const activeLayouts = (appData.layouts || []).filter(l => l && l.name && !/^Перед изменением/i.test(l.name));
          return sendJson(res, 200, { layouts: activeLayouts });
        }
        if (!hasPermission(auth.user, 'layouts.manage')) {
          store.logEvent({ action: 'layouts.modify.denied', actor: auth.user, ip, userAgent, status: 'denied' });
          return sendJson(res, 403, { error: 'Недостаточно прав для сохранения или удаления макетов.' });
        }
        if (method === 'DELETE') {
          if (auth.user.role === 'HEAD' || !hasPermission(auth.user, 'layouts.delete')) {
            store.logEvent({ action: 'layouts.delete.denied', actor: auth.user, target: id, ip, userAgent, status: 'denied' });
            return sendJson(res, 403, { error: 'У вашей роли нет прав на удаление макетов.' });
          }
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

      // User personal preferences (Theme & Custom themes synced per user account across devices)
      if (pathname === '/api/user/preferences' && method === 'GET') {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        return sendJson(res, 200, {
          ok: true,
          theme: auth.user.theme || null,
          customThemes: Array.isArray(auth.user.customThemes) ? auth.user.customThemes : []
        });
      }

      if (pathname === '/api/user/preferences' && method === 'POST') {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        const body = await readBody(req);
        if (body.theme !== undefined && typeof body.theme === 'object') {
          auth.user.theme = body.theme;
        }
        if (Array.isArray(body.customThemes)) {
          auth.user.customThemes = body.customThemes.slice(0, 50);
        }
        auth.user.updatedAt = Date.now();
        store.saveUsers();
        return sendJson(res, 200, {
          ok: true,
          theme: auth.user.theme || null,
          customThemes: Array.isArray(auth.user.customThemes) ? auth.user.customThemes : []
        });
      }

      // Users management: GET /api/users, POST /api/users, PATCH /api/users/:id, DELETE /api/users/:id
      if (pathname === '/api/users' || pathname.startsWith('/api/users/')) {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        const targetId = pathname.split('/')[3] || null;
        const isOwner = auth.user.role === 'OWNER';
        const isHead = auth.user.role === 'HEAD';
        const canManageAllUsers = isOwner || (!isHead && hasPermission(auth.user, 'users.manage'));
        const canManageOwnTeam = isHead && hasPermission(auth.user, 'users.manage');

        // List users: OWNER, HEAD, or user with users.view / users.manage permission
        if (method === 'GET' && !targetId) {
          if (!isOwner && !isHead && !hasPermission(auth.user, 'users.view') && !hasPermission(auth.user, 'users.manage')) {
            return sendJson(res, 403, { error: 'Доступ к списку пользователей разрешён только Владельцу, Администраторам и Руководителям отдела.' });
          }
          const activeSessions = store.getSessions();
          const allUsers = store.getUsers();
          const visibleUsers = isHead
            ? allUsers.filter(u => u.id === auth.user.id || (u.role === 'OPERATOR' && u.managerId === auth.user.id))
            : allUsers;
          const list = visibleUsers.map(u => ({
            ...sanitizeUser(u),
            activeSessionsCount: activeSessions.filter(s => s.userId === u.id).length
          }));
          const heads = allUsers
            .filter(u => u.role === 'HEAD' || u.role === 'OWNER')
            .map(u => ({
              id: u.id,
              login: u.login,
              displayName: u.displayName || u.login,
              role: u.role,
              isOwner: u.role === 'OWNER',
              departmentScripts: Array.isArray(u.departmentScripts) ? u.departmentScripts : [],
              departmentScriptsCount: Array.isArray(u.departmentScripts) ? u.departmentScripts.length : 0
            }));
          return sendJson(res, 200, { users: list, heads, availablePermissions: ALL_PERMISSIONS, roleDefaults: DEFAULT_ROLE_PERMISSIONS });
        }

        if (!canManageAllUsers && !canManageOwnTeam) {
          store.logEvent({
            action: 'users.manage.denied',
            actor: auth.user,
            target: targetId,
            ip,
            userAgent,
            status: 'denied',
            details: { method, pathname }
          });
          return sendJson(res, 403, { error: 'Недостаточно прав для управления учётными записями.' });
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
          if (isHead && body.role && body.role !== 'OPERATOR') {
            return sendJson(res, 403, { error: 'Руководитель отдела может добавлять только Менеджеров обзвона.' });
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
          const role = isHead
            ? 'OPERATOR'
            : (['ADMIN', 'EDITOR', 'HEAD', 'OPERATOR'].includes(body.role) ? body.role : 'OPERATOR');
          const permissions = isHead
            ? [...(DEFAULT_ROLE_PERMISSIONS.OPERATOR || [])]
            : (Array.isArray(body.permissions)
                ? body.permissions.filter(p => ALL_PERMISSIONS.includes(p))
                : [...(DEFAULT_ROLE_PERMISSIONS[role] || [])]);
          let managerId = null;
          if (role === 'OPERATOR') {
            if (isHead) {
              managerId = auth.user.id;
            } else if (body.managerId) {
              const mgr = store.findUserById(String(body.managerId));
              if (mgr && (mgr.role === 'HEAD' || mgr.role === 'OWNER')) managerId = mgr.id;
            } else if (isOwner) {
              managerId = auth.user.id;
            }
          }
          const now = Date.now();
          const newUser = {
            id: 'usr_' + crypto.randomUUID(),
            login,
            displayName: String(body.displayName || login).trim().slice(0, 100) || login,
            role,
            managerId,
            passwordHash: hashPassword(body.password),
            mustChangePassword: body.mustChangePassword !== undefined ? Boolean(body.mustChangePassword) : true,
            blocked: Boolean(body.blocked),
            permissions,
            permissionsMigratedV2: true,
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
            details: { userId: newUser.id, role: newUser.role, managerId: newUser.managerId, permissions: newUser.permissions, blocked: newUser.blocked }
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
            // Protect OWNER from any modification by non-OWNER, and from self-demotion/self-block
            if (!isOwner || body.blocked === true || (body.role !== undefined && body.role !== 'OWNER') || body.permissions !== undefined) {
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

          if (isHead) {
            if (targetUser.role !== 'OPERATOR' || targetUser.managerId !== auth.user.id) {
              return sendJson(res, 403, { error: 'Руководитель отдела может управлять только своими Менеджерами обзвона.' });
            }
            if (body.role !== undefined && body.role !== 'OPERATOR') {
              return sendJson(res, 403, { error: 'Руководитель отдела не может менять роль сотрудника.' });
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

          if (!isHead && body.role !== undefined && targetUser.role !== 'OWNER') {
            if (!['ADMIN', 'EDITOR', 'HEAD', 'OPERATOR'].includes(body.role)) {
              return sendJson(res, 400, { error: 'Недопустимая роль пользователя.' });
            }
            changes.role = { from: targetUser.role, to: body.role };
            targetUser.role = body.role;
            if (targetUser.role !== 'OPERATOR') {
              targetUser.managerId = null;
            }
          }

          if (!isHead && body.managerId !== undefined && targetUser.role === 'OPERATOR') {
            let nextMgr = null;
            if (body.managerId) {
              const mgr = store.findUserById(String(body.managerId));
              if (mgr && (mgr.role === 'HEAD' || mgr.role === 'OWNER')) nextMgr = mgr.id;
            }
            if ((targetUser.managerId || null) !== nextMgr) {
              changes.managerId = { from: targetUser.managerId || null, to: nextMgr };
              targetUser.managerId = nextMgr;
            }
          }

          if (body.departmentScripts !== undefined && (targetUser.role === 'HEAD' || targetUser.role === 'OWNER')) {
            targetUser.departmentScripts = Array.isArray(body.departmentScripts) ? body.departmentScripts.map(String) : [];
            changes.departmentScripts = targetUser.departmentScripts;
          }

          if (!isHead && body.permissions !== undefined && targetUser.role !== 'OWNER') {
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
            targetUser.mustChangePassword = true;
            changes.passwordReset = true;
            changes.mustChangePassword = true;
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
          if (isHead) {
            store.logEvent({
              action: 'users.delete.denied',
              actor: auth.user,
              target: targetId,
              ip,
              userAgent,
              status: 'denied'
            });
            return sendJson(res, 403, { error: 'Руководитель отдела не может удалять учётные записи (доступна блокировка).' });
          }
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
        const isOwner = auth.user.role === 'OWNER';
        const isHead = auth.user.role === 'HEAD';
        if (!isOwner && !isHead && !hasPermission(auth.user, 'sessions.manage')) {
          store.logEvent({ action: 'sessions.access.denied', actor: auth.user, ip, userAgent, status: 'denied' });
          return sendJson(res, 403, { error: 'Недостаточно прав для управления сессиями.' });
        }
        const canAccessUserSession = (u) => {
          if (!u) return !isHead;
          if (isOwner) return true;
          if (isHead) return u.id === auth.user.id || (u.role === 'OPERATOR' && u.managerId === auth.user.id);
          return u.role !== 'OWNER';
        };

        const sub = pathname.split('/')[3] || null;
        if (method === 'GET' && !sub) {
          const list = store.getSessions()
            .filter(s => {
              const u = store.findUserById(s.userId);
              return isOwner || canAccessUserSession(u);
            })
            .map(s => {
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
          if (!canAccessUserSession(targetUser)) {
            return sendJson(res, 403, { error: 'Недостаточно прав для сброса сессий этого пользователя.' });
          }
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
          const targetSes = store.getSessions().find(s => s.id === sub);
          if (!targetSes) return sendJson(res, 404, { error: 'Сессия не найдена или уже завершена.' });
          const targetUser = store.findUserById(targetSes.userId);
          if (!canAccessUserSession(targetUser)) {
            return sendJson(res, 403, { error: 'Недостаточно прав для завершения этой сессии.' });
          }
          const removed = store.revokeSessionById(sub);
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

      // Activity tracking: POST /api/audit/track
      if (pathname === '/api/audit/track' && method === 'POST') {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        const body = await parseJson(req);
        const action = String(body.action || 'activity.clicks').trim();
        const target = body.target ? String(body.target).slice(0, 200) : null;
        const details = (typeof body.details === 'object' && body.details !== null) ? body.details : {};
        const clicks = Math.max(1, Math.min(1000, Number(body.clicks || details.count || 1)));
        details.clicks = clicks;

        const entry = store.logEvent({
          action,
          actor: auth.user,
          target,
          ip,
          userAgent,
          details,
          status: 'success'
        });
        return sendJson(res, 200, { ok: true, id: entry.id });
      }

      // Audit log: GET /api/audit
      if (pathname === '/api/audit' && method === 'GET') {
        if (!auth) return sendJson(res, 401, { error: 'Требуется авторизация.' });
        const isOwner = auth.user.role === 'OWNER';
        const isHead = auth.user.role === 'HEAD';
        const isAdmin = auth.user.role === 'ADMIN';
        const hasAuditPerm = hasPermission(auth.user, 'audit.view');

        if (!isOwner && !isHead && !hasAuditPerm) {
          store.logEvent({ action: 'audit.access.denied', actor: auth.user, ip, userAgent, status: 'denied' });
          return sendJson(res, 403, { error: 'Журнал действий доступен только Владельцу, Администраторам и Руководителям отдела.' });
        }

        const limit = Math.min(1000, Math.max(10, Number(url.searchParams.get('limit')) || 300));
        const filterUser = (url.searchParams.get('user') || '').trim().toLowerCase();
        const filterAction = (url.searchParams.get('action') || '').trim().toLowerCase();
        const filterDepartment = (url.searchParams.get('department') || '').trim();
        const filterPeriod = (url.searchParams.get('period') || 'all').trim().toLowerCase();

        const allUsers = store.getUsers();
        const heads = allUsers.filter(u => u.role === 'HEAD' || u.role === 'OWNER');

        // Department isolation for HEAD (unless has global audit.view)
        const isRestrictedHead = isHead && !isOwner && !hasAuditPerm;
        let visibleUsers = allUsers;
        let departments = [];

        if (isRestrictedHead) {
          visibleUsers = allUsers.filter(u => u.id === auth.user.id || (u.role === 'OPERATOR' && u.managerId === auth.user.id));
          departments = [{ id: auth.user.id, name: 'Мой отдел (' + (auth.user.displayName || auth.user.login) + ')' }];
        } else {
          departments = heads.map(h => ({
            id: h.id,
            name: (h.displayName || h.login) + (h.role === 'OWNER' ? ' (Владелец)' : ' (Руководитель отдела)')
          }));
        }

        const visibleLogins = new Set(visibleUsers.map(u => normalizeLogin(u.login)));
        const visibleIds = new Set(visibleUsers.map(u => u.id));

        let entries = [...store.getAudit()].reverse();

        // 1. Enforce team/department restriction for HEAD
        if (isRestrictedHead) {
          entries = entries.filter(e =>
            visibleIds.has(e.actorId) ||
            visibleLogins.has(normalizeLogin(e.actorLogin)) ||
            visibleLogins.has(normalizeLogin(e.target))
          );
        } else if (filterDepartment) {
          if (filterDepartment === 'none') {
            const unassignedUsers = allUsers.filter(u => !u.managerId && u.role !== 'OWNER');
            const unassignedLogins = new Set(unassignedUsers.map(u => normalizeLogin(u.login)));
            entries = entries.filter(e => unassignedLogins.has(normalizeLogin(e.actorLogin)));
          } else {
            const deptUsers = allUsers.filter(u => u.id === filterDepartment || u.managerId === filterDepartment);
            const deptLogins = new Set(deptUsers.map(u => normalizeLogin(u.login)));
            entries = entries.filter(e => deptLogins.has(normalizeLogin(e.actorLogin)) || deptLogins.has(normalizeLogin(e.target)));
          }
        }

        // 2. Period filtering
        const now = Date.now();
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);
        const todayTs = todayStart.getTime();

        if (filterPeriod === 'today') {
          entries = entries.filter(e => e.timestamp >= todayTs);
        } else if (filterPeriod === '3days') {
          entries = entries.filter(e => e.timestamp >= (now - 3 * 86400000));
        } else if (filterPeriod === 'week') {
          entries = entries.filter(e => e.timestamp >= (now - 7 * 86400000));
        }

        // 3. User / Search filtering
        if (filterUser) {
          entries = entries.filter(e =>
            (e.actorLogin || '').toLowerCase().includes(filterUser) ||
            (e.actorName || '').toLowerCase().includes(filterUser) ||
            (e.target || '').toLowerCase().includes(filterUser)
          );
        }

        // 4. Action filtering
        if (filterAction) {
          if (filterAction === 'operator') {
            entries = entries.filter(e => (e.action || '').startsWith('activity.'));
          } else if (filterAction === 'auth') {
            entries = entries.filter(e => (e.action || '').startsWith('auth.') || (e.action || '').startsWith('owner.recovery'));
          } else if (filterAction === 'users') {
            entries = entries.filter(e => (e.action || '').startsWith('users.') || e.action === 'user.password.changed');
          } else if (filterAction === 'layouts') {
            entries = entries.filter(e => (e.action || '').startsWith('layouts.') || e.action === 'content.publish');
          } else {
            entries = entries.filter(e => (e.action || '').toLowerCase().includes(filterAction));
          }
        }

        // 5. Aggregate employee activity and click statistics
        const statsMap = new Map();
        visibleUsers.forEach(u => {
          const mgr = heads.find(h => h.id === u.managerId);
          statsMap.set(u.id, {
            id: u.id,
            login: u.login,
            displayName: u.displayName || u.login,
            role: u.role,
            managerId: u.managerId || null,
            managerName: mgr ? (mgr.displayName || mgr.login) : (u.role === 'OWNER' ? 'Владелец' : '—'),
            clicksToday: 0,
            clicksPeriod: 0,
            lastAction: null,
            lastActionDetails: null,
            lastTimestamp: null,
            isOnline: false
          });
        });

        const fullAudit = store.getAudit();
        for (let i = 0; i < fullAudit.length; i++) {
          const ev = fullAudit[i];
          const stat = statsMap.get(ev.actorId) || [...statsMap.values()].find(s => normalizeLogin(s.login) === normalizeLogin(ev.actorLogin));
          if (!stat) continue;

          const clicks = Number(ev.details?.clicks || ev.details?.count || 1);
          if (ev.timestamp >= todayTs) {
            stat.clicksToday += clicks;
          }
          if (filterPeriod === 'today') {
            if (ev.timestamp >= todayTs) stat.clicksPeriod += clicks;
          } else if (filterPeriod === '3days') {
            if (ev.timestamp >= (now - 3 * 86400000)) stat.clicksPeriod += clicks;
          } else if (filterPeriod === 'week') {
            if (ev.timestamp >= (now - 7 * 86400000)) stat.clicksPeriod += clicks;
          } else {
            stat.clicksPeriod += clicks;
          }

          if (!stat.lastTimestamp || ev.timestamp > stat.lastTimestamp) {
            stat.lastTimestamp = ev.timestamp;
            stat.lastAction = ev.action;
            stat.lastActionDetails = ev.details;
          }
        }

        const stats = [...statsMap.values()].map(s => {
          s.isOnline = s.lastTimestamp ? (now - s.lastTimestamp) < 5 * 60 * 1000 : false;
          return s;
        }).sort((a, b) => (b.clicksToday - a.clicksToday) || ((b.lastTimestamp || 0) - (a.lastTimestamp || 0)));

        return sendJson(res, 200, {
          events: entries.slice(0, limit),
          total: entries.length,
          stats,
          departments,
          isHead: isRestrictedHead
        });
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
  const host = process.env.HOST || '0.0.0.0';
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

let defaultVercelApp = null;
function vercelHandler(req, res) {
  if (!defaultVercelApp) {
    defaultVercelApp = createAppServer({ dataDir: DEFAULT_DATA_DIR, htmlPath: INDEX_PATH });
  }
  defaultVercelApp.server.emit('request', req, res);
}

vercelHandler.createAppServer = createAppServer;
vercelHandler.ALL_PERMISSIONS = ALL_PERMISSIONS;
vercelHandler.DEFAULT_ROLE_PERMISSIONS = DEFAULT_ROLE_PERMISSIONS;
vercelHandler.hashPassword = hashPassword;
vercelHandler.verifyPassword = verifyPassword;
vercelHandler.default = vercelHandler;

module.exports = vercelHandler;
