'use strict';

process.on('uncaughtException', (err) => {
  console.error('CRITICAL UNCAUGHT EXCEPTION:', err && err.stack ? err.stack : err);
});

process.on('unhandledRejection', (reason) => {
  console.error('CRITICAL UNHANDLED REJECTION:', reason && reason.stack ? reason.stack : reason);
});

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');

// Choose the first writable directory from candidates
function resolveWritableDataDir(preferredDir) {
  const candidates = [
    preferredDir,
    path.join(__dirname, 'data'),
    path.join(os.tmpdir(), 'bauer-data')
  ].filter(Boolean);

  for (const candidate of candidates) {
    try {
      fs.mkdirSync(candidate, { recursive: true });
      const testFile = path.join(candidate, `.test-${Date.now()}-${process.pid}`);
      fs.writeFileSync(testFile, 'test');
      fs.unlinkSync(testFile);
      return candidate;
    } catch (err) {
      console.warn(`[start.js] Directory "${candidate}" is not writable (${err.message}). Trying next...`);
    }
  }
  const fallback = path.join(os.tmpdir(), 'bauer-data');
  try { fs.mkdirSync(fallback, { recursive: true }); } catch {}
  return fallback;
}

function copySeedFilesIfMissing(targetDir) {
  const seedDir = path.join(__dirname, 'data');
  if (path.resolve(targetDir) === path.resolve(seedDir) || !fs.existsSync(seedDir)) return;
  const filesToSeed = ['users.json', 'app-data.json', 'shared-themes.json'];
  for (const file of filesToSeed) {
    const src = path.join(seedDir, file);
    const dest = path.join(targetDir, file);
    try {
      if (fs.existsSync(src) && !fs.existsSync(dest)) {
        fs.copyFileSync(src, dest);
        console.log(`[start.js] Seed file initialized: ${file} -> ${targetDir}`);
      }
    } catch (e) {
      console.warn(`[start.js] Could not seed ${file}:`, e.message);
    }
  }
}

const safeDataDir = resolveWritableDataDir(process.env.BAUER_DATA_DIR || '/data');
copySeedFilesIfMissing(safeDataDir);
process.env.BAUER_DATA_DIR = safeDataDir;
process.env.HOST = process.env.HOST || '0.0.0.0';
process.env.PORT = process.env.PORT || '3000';

const { createAppServer } = require('./server');

const port = Number(process.env.PORT) || 3000;
const host = process.env.HOST || '0.0.0.0';

try {
  const { server, store } = createAppServer({ dataDir: safeDataDir });

  server.on('error', (err) => {
    console.error('SERVER HTTP ERROR:', err && err.stack ? err.stack : err);
  });

  server.listen(port, host, () => {
    let ownerLogin = 'не создан';
    try {
      const owner = store.getOwner();
      if (owner) ownerLogin = owner.login;
    } catch (e) {
      console.warn('Owner lookup warning:', e.message);
    }

    console.log('============================================================');
    console.log(`BAUER сервер запущен: http://${host}:${port}`);
    console.log(`Владелец (OWNER): ${ownerLogin}`);
    console.log(`Директория данных: ${safeDataDir}`);
    console.log('============================================================');
  });

} catch (err) {
  console.error('FATAL ERROR DURING createAppServer:', err && err.stack ? err.stack : err);
}
