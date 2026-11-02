'use strict';

// Одноразовая выгрузка данных BAUER из Vercel Blob в локальную папку
// data-export/, в формате, который понимает server.js (папка данных).
//
// Запуск (с включённым VPN, т.к. Vercel может быть недоступен):
//   $env:BLOB_READ_WRITE_TOKEN="vercel_blob_rw_..."; node tools/export-vercel-data.js
//
// Затем содержимое data-export/ загружается в папку /data на Amvera.

const fs = require('node:fs');
const path = require('node:path');
const { get } = require('@vercel/blob');

const OUT = path.join(__dirname, '..', 'data-export');

async function readBlob(name) {
  const res = await get(`bauer-state/${name}`, { access: 'private', useCache: false });
  if (!res || res.statusCode !== 200 || !res.stream) return null;
  return new Response(res.stream).json();
}

function write(file, data) {
  fs.writeFileSync(path.join(OUT, file), JSON.stringify(data, null, 2), 'utf8');
  const count = Array.isArray(data) ? `${data.length} записей` : 'объект';
  console.log(`  ✓ ${file} (${count})`);
}

(async () => {
  if (!process.env.BLOB_READ_WRITE_TOKEN) {
    console.error('Не задан BLOB_READ_WRITE_TOKEN.');
    process.exit(1);
  }
  fs.mkdirSync(OUT, { recursive: true });
  console.log('Выгрузка из Vercel Blob в', OUT);

  const auth = await readBlob('auth.json');
  if (auth) {
    write('users.json', auth.users || []);
    write('sessions.json', auth.sessions || []);
    write('audit.json', auth.audit || []);
  } else {
    console.warn('  ! auth.json не найден');
  }

  const appData = await readBlob('app-data.json');
  if (appData) write('app-data.json', appData);
  else console.warn('  ! app-data.json не найден');

  const themes = await readBlob('shared-themes.json');
  write('shared-themes.json', Array.isArray(themes) ? themes : []);

  console.log('Готово.');
})().catch(err => {
  console.error('Ошибка выгрузки:', err.message);
  process.exit(1);
});
