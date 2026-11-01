'use strict';

const path = require('node:path');
const os = require('node:os');
const { createAppServer } = require('../server');

const dataDir = process.env.BAUER_DATA_DIR || path.join(os.tmpdir(), 'bauer-data');
const htmlPath = path.join(__dirname, '..', 'index.html');
const { server } = createAppServer({ dataDir, htmlPath });

module.exports = (req, res) => {
  server.emit('request', req, res);
};
