const test = require('node:test');
const assert = require('node:assert');
const db = require('../server/db/connection');
const { runMigrations } = require('../server/db/migrations/setup');
const { v4: uuidv4 } = require('uuid');

runMigrations();

test('Phase 8: Database setup', async (t) => {
  await t.test('user_sessions table exists', () => {
    const stmt = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='user_sessions'");
    const row = stmt.get();
    assert.strictEqual(row.name, 'user_sessions');
  });

  await t.test('auth_tokens table exists', () => {
    const stmt = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='auth_tokens'");
    const row = stmt.get();
    assert.strictEqual(row.name, 'auth_tokens');
  });

  await t.test('security_events table exists', () => {
    const stmt = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'");
    const row = stmt.get();
    assert.strictEqual(row.name, 'security_events');
  });

  await t.test('mfa_secrets table exists', () => {
    const stmt = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='mfa_secrets'");
    const row = stmt.get();
    assert.strictEqual(row.name, 'mfa_secrets');
  });
});

test('Phase 8: Security Events', async (t) => {
  await t.test('Can insert and retrieve security event', () => {
    const eventId = uuidv4();
    const userId = uuidv4();
    
    db.prepare('INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)').run(userId, `eventtest_${uuidv4()}@example.com`, 'hash');
    
    db.prepare(`
      INSERT INTO security_events (id, user_id, event_type, success, metadata)
      VALUES (?, ?, ?, ?, ?)
    `).run(eventId, userId, 'LOGIN_SUCCESS', 1, '{}');
    
    const event = db.prepare('SELECT event_type FROM security_events WHERE id = ?').get(eventId);
    assert.strictEqual(event.event_type, 'LOGIN_SUCCESS');
  });
});

test('Phase 8: Auth Tokens', async (t) => {
  await t.test('Can insert and invalidate tokens', () => {
    const tokenId = uuidv4();
    const userId = uuidv4();
    
    db.prepare('INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)').run(userId, `tokentest_${uuidv4()}@example.com`, 'hash');
    
    db.prepare(`
      INSERT INTO auth_tokens (id, user_id, token_hash, token_type, expires_at)
      VALUES (?, ?, ?, 'EMAIL_VERIFICATION', datetime('now', '+1 day'))
    `).run(tokenId, userId, 'testhash');
    
    const token = db.prepare('SELECT token_hash, is_used FROM auth_tokens WHERE id = ?').get(tokenId);
    assert.strictEqual(token.token_hash, 'testhash');
    assert.strictEqual(token.is_used, 0);
    
    db.prepare('UPDATE auth_tokens SET is_used = 1 WHERE id = ?').run(tokenId);
    const updated = db.prepare('SELECT is_used FROM auth_tokens WHERE id = ?').get(tokenId);
    assert.strictEqual(updated.is_used, 1);
  });
});
