const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dbDir = path.join(__dirname, '..', '..', 'data');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = process.env.NODE_ENV === 'test' 
  ? ':memory:' 
  : path.join(dbDir, 'trust_verify.sqlite');

const db = new Database(dbPath, { verbose: null });

db.pragma('journal_mode = WAL');

module.exports = db;
