'use strict';

process.on('uncaughtException', (err) => {
  console.error('CRITICAL UNCAUGHT EXCEPTION:', err && err.stack ? err.stack : err);
});

process.on('unhandledRejection', (reason) => {
  console.error('CRITICAL UNHANDLED REJECTION:', reason && reason.stack ? reason.stack : reason);
});

process.env.HOST = process.env.HOST || '0.0.0.0';
process.env.PORT = process.env.PORT || '3000';
process.env.BAUER_DATA_DIR = process.env.BAUER_DATA_DIR || '/data';

const fs = require('node:fs');
const http = require('node:http');

try {
  fs.mkdirSync(process.env.BAUER_DATA_DIR, { recursive: true });
} catch (e) {
  console.warn('Data directory creation warning:', e.message);
}

const { createAppServer } = require('./server');

const port = Number(process.env.PORT) || 3000;
const host = process.env.HOST || '0.0.0.0';

try {
  const { server, store } = createAppServer({ dataDir: process.env.BAUER_DATA_DIR });

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
    console.log(`Директория данных: ${process.env.BAUER_DATA_DIR}`);
    console.log('============================================================');
  });

  // If port is 3000, also bind to port 80 as a fallback if permissible
  if (port !== 80) {
    try {
      const p80 = http.createServer((req, res) => server.emit('request', req, res));
      p80.listen(80, host).on('error', () => {});
    } catch {}
  }
} catch (err) {
  console.error('FATAL ERROR DURING createAppServer:', err && err.stack ? err.stack : err);
}
