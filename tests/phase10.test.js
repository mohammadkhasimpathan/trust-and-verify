const test = require('node:test');
const assert = require('node:assert');
const db = require('../server/db/connection');
const { runMigrations } = require('../server/db/migrations/setup');
const { v4: uuidv4 } = require('uuid');
const { hasPermission, PERMISSIONS, ROLES } = require('../server/authorization/permissions');

runMigrations();

test('Phase 10: Database setup', async (t) => {
  const tables = [
    'indicators', 'security_incidents', 'incident_events', 'incident_iocs', 
    'investigations', 'security_campaigns', 'campaign_events'
  ];
  
  for (const table of tables) {
    await t.test(`${table} table exists`, () => {
      const stmt = db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`);
      assert.strictEqual(stmt.get(table).name, table);
    });
  }
});

test('Phase 10: RBAC Permissions', async (t) => {
  await t.test('Owner has all permissions', () => {
    assert.ok(hasPermission(ROLES.OWNER, PERMISSIONS.INCIDENTS_CLOSE));
    assert.ok(hasPermission(ROLES.OWNER, PERMISSIONS.CAMPAIGNS_LAUNCH));
  });

  await t.test('Admin can manage campaigns', () => {
    assert.ok(hasPermission(ROLES.ADMIN, PERMISSIONS.CAMPAIGNS_LAUNCH));
    assert.ok(hasPermission(ROLES.ADMIN, PERMISSIONS.IOCS_ENRICH));
  });

  await t.test('Member can read but not launch campaigns', () => {
    assert.strictEqual(hasPermission(ROLES.MEMBER, PERMISSIONS.CAMPAIGNS_LAUNCH), false);
    assert.ok(hasPermission(ROLES.MEMBER, PERMISSIONS.INCIDENTS_READ));
  });
});

test('Phase 10: DB Constraints', async (t) => {
  const userId = uuidv4();
  db.prepare('INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)').run(userId, `secops_${uuidv4()}@example.com`, 'hash');

  const orgId = uuidv4();
  db.prepare('INSERT INTO organizations (id, name, slug, owner_user_id) VALUES (?, ?, ?, ?)').run(orgId, 'SecOps Org', `secops-org-${uuidv4()}`, userId);

  await t.test('Can create IOC', () => {
    const iocId = uuidv4();
    db.prepare(`
      INSERT INTO indicators (id, organization_id, type, value, normalized_value, fingerprint, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(iocId, orgId, 'Domain', 'example.com', 'example.com', `fingerprint1_${uuidv4()}`, userId);
    
    const count = db.prepare('SELECT COUNT(*) as c FROM indicators WHERE id = ?').get(iocId).c;
    assert.strictEqual(count, 1);
  });

  await t.test('IOC fingerprint is unique', () => {
    assert.throws(() => {
      db.prepare(`
        INSERT INTO indicators (id, organization_id, type, value, normalized_value, fingerprint, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(uuidv4(), orgId, 'Domain', 'EXAMPLE.COM', 'example.com', 'fingerprint_dup', userId);
      
      db.prepare(`
        INSERT INTO indicators (id, organization_id, type, value, normalized_value, fingerprint, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(uuidv4(), orgId, 'Domain', 'EXAMPLE.COM', 'example.com', 'fingerprint_dup', userId);
    }, /UNIQUE constraint failed/);
  });

  await t.test('Can create Security Incident', () => {
    const incId = uuidv4();
    db.prepare(`
      INSERT INTO security_incidents (id, organization_id, title, category, severity, created_by)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(incId, orgId, 'Suspicious Login', 'ACCOUNT_COMPROMISE', 'HIGH', userId);
    
    const count = db.prepare('SELECT COUNT(*) as c FROM security_incidents WHERE id = ?').get(incId).c;
    assert.strictEqual(count, 1);
  });
});
