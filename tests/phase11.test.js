const test = require('node:test');
const assert = require('node:assert');
const db = require('../server/db/connection');
const { runMigrations } = require('../server/db/migrations/setup');
const { v4: uuidv4 } = require('uuid');
const { hasPermission, PERMISSIONS, ROLES } = require('../server/authorization/permissions');
const { isSafeUrl } = require('../server/integrations/webhookService');

runMigrations();

test('Phase 11: Database setup', async (t) => {
  const tables = [
    'integrations', 'integration_credentials', 'webhook_endpoints', 'webhook_deliveries', 
    'api_keys', 'service_accounts'
  ];
  
  for (const table of tables) {
    await t.test(`${table} table exists`, () => {
      const stmt = db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`);
      assert.strictEqual(stmt.get(table).name, table);
    });
  }
});

test('Phase 11: RBAC Permissions', async (t) => {
  await t.test('Owner has integration permissions', () => {
    assert.ok(hasPermission(ROLES.OWNER, PERMISSIONS.INTEGRATIONS_CREATE));
  });

  await t.test('Member does not have integration manage permissions', () => {
    assert.strictEqual(hasPermission(ROLES.MEMBER, PERMISSIONS.WEBHOOKS_CREATE), false);
    assert.ok(hasPermission(ROLES.MEMBER, PERMISSIONS.API_ACCESS));
  });
});

test('Phase 11: Webhook SSRF validation', async (t) => {
  await t.test('Accepts valid HTTPS URL', async () => {
    assert.strictEqual(await isSafeUrl('https://example.com/webhook'), true);
  });

  await t.test('Rejects localhost', async () => {
    assert.strictEqual(await isSafeUrl('http://localhost:8080'), false);
    assert.strictEqual(await isSafeUrl('http://127.0.0.1/test'), false);
  });
  
  await t.test('Rejects private IPs', async () => {
    assert.strictEqual(await isSafeUrl('http://192.168.1.1'), false);
    assert.strictEqual(await isSafeUrl('http://10.0.0.5'), false);
  });
});

test('Phase 11: API Keys & Credentials', async (t) => {
  const { createApiKey, verifyApiKey, createIntegration, getIntegrationCredentials } = require('../server/integrations/integrationRegistry');

  const userId = uuidv4();
  db.prepare('INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)').run(userId, `phase11_${uuidv4()}@example.com`, 'hash');

  const orgId = uuidv4();
  db.prepare('INSERT INTO organizations (id, name, slug, owner_user_id) VALUES (?, ?, ?, ?)').run(orgId, 'Phase 11 Org', `phase11-org-${uuidv4()}`, userId);

  await t.test('Can create and verify API key', () => {
    const keyResult = createApiKey(orgId, userId, null, 'Test Key', ['api.access']);
    assert.ok(keyResult.key.startsWith('tvk_live_'));
    
    const verification = verifyApiKey(keyResult.key);
    assert.ok(verification);
    assert.strictEqual(verification.organizationId, orgId);
    assert.deepStrictEqual(verification.scopes, ['api.access']);
  });

  await t.test('Cannot verify invalid API key', () => {
    const verification = verifyApiKey('tvk_live_invalidkey123');
    assert.strictEqual(verification, null);
  });

  await t.test('Can encrypt and decrypt integration secret', () => {
    const secret = 'super_secret_splunk_token';
    const intId = createIntegration(orgId, userId, 'SIEM', 'Splunk Prod', 'splunk', { url: 'https://splunk.example.com' }, secret);
    
    const decrypted = getIntegrationCredentials(orgId, intId);
    assert.strictEqual(decrypted, secret);
  });
});
