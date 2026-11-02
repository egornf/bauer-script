'use strict';

// Точка запуска для хостинга Amvera (и любого VPS/контейнера).
// Задаём значения по умолчанию ДО загрузки server.js, потому что он
// вычисляет папку данных при импорте.
process.env.HOST = process.env.HOST || '0.0.0.0';
process.env.PORT = process.env.PORT || '3000';
process.env.BAUER_DATA_DIR = process.env.BAUER_DATA_DIR || '/data';

const fs = require('node:fs');
try { fs.mkdirSync(process.env.BAUER_DATA_DIR, { recursive: true }); } catch {}

const { createAppServer } = require('./server');

const port = Number(process.env.PORT);
const host = process.env.HOST;
const { server, store } = createAppServer({ dataDir: process.env.BAUER_DATA_DIR });

server.listen(port, host, () => {
  const owner = store.getOwner();
  console.log('============================================================');
  console.log(`BAUER запущен: http://${host}:${port}`);
  console.log(`OWNER: ${owner ? owner.login : 'ожидает первичной настройки'}`);
  console.log(`Хранилище данных: ${process.env.BAUER_DATA_DIR}`);
  console.log('============================================================');
});
