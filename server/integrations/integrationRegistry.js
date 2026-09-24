const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/connection');

// Encryption key for secrets (in a real app this should be heavily protected in env)
const ENCRYPTION_KEY = process.env.INTEGRATION_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  // Ensure the key is 32 bytes for aes-256-cbc
  const keyBuffer = Buffer.alloc(32);
  Buffer.from(ENCRYPTION_KEY, 'hex').copy(keyBuffer);
  
  const cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  const textParts = text.split(':');
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encryptedText = Buffer.from(textParts.join(':'), 'hex');
  const keyBuffer = Buffer.alloc(32);
  Buffer.from(ENCRYPTION_KEY, 'hex').copy(keyBuffer);

  const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

function createIntegration(orgId, userId, type, name, provider, configuration, secret) {
  const id = uuidv4();
  db.transaction(() => {
    db.prepare(`
      INSERT INTO integrations (id, organization_id, type, name, provider, configuration, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, orgId, type, name, provider, JSON.stringify(configuration), userId);

    if (secret) {
      db.prepare(`
        INSERT INTO integration_credentials (integration_id, organization_id, encrypted_secret)
        VALUES (?, ?, ?)
      `).run(id, orgId, encrypt(secret));
    }
  })();
  return id;
}

function getIntegrations(orgId) {
  return db.prepare('SELECT id, type, name, provider, status, created_at FROM integrations WHERE organization_id = ?').all(orgId);
}

function getIntegrationCredentials(orgId, integrationId) {
  const cred = db.prepare('SELECT encrypted_secret FROM integration_credentials WHERE organization_id = ? AND integration_id = ?').get(orgId, integrationId);
  return cred ? decrypt(cred.encrypted_secret) : null;
}

function createApiKey(orgId, userId, serviceAccountId, name, scopes) {
  const rawKey = crypto.randomBytes(32).toString('hex');
  const prefix = 'tvk_live_' + crypto.randomBytes(4).toString('hex');
  const fullKey = prefix + '_' + rawKey;
  
  const keyHash = crypto.createHash('sha256').update(fullKey).digest('hex');
  const id = uuidv4();

  db.prepare(`
    INSERT INTO api_keys (id, organization_id, service_account_id, name, prefix, key_hash, scopes, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, orgId, serviceAccountId || null, name, prefix, keyHash, JSON.stringify(scopes), userId);

  return { id, key: fullKey, prefix }; // raw key only returned once
}

function verifyApiKey(key) {
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');
  const record = db.prepare("SELECT * FROM api_keys WHERE key_hash = ? AND status = 'ACTIVE'").get(keyHash);
  if (record) {
    db.prepare('UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?').run(record.id);
    return {
      organizationId: record.organization_id,
      scopes: JSON.parse(record.scopes || '[]')
    };
  }
  return null;
}

function createServiceAccount(orgId, userId, name, description) {
  const id = uuidv4();
  db.prepare(`
    INSERT INTO service_accounts (id, organization_id, name, description, created_by)
    VALUES (?, ?, ?, ?, ?)
  `).run(id, orgId, name, description, userId);
  return id;
}

module.exports = {
  createIntegration,
  getIntegrations,
  getIntegrationCredentials,
  createApiKey,
  verifyApiKey,
  createServiceAccount
};
