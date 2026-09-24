const test = require('node:test');
const assert = require('node:assert');
const db = require('../server/db/connection');
const { runMigrations } = require('../server/db/migrations/setup');
const { v4: uuidv4 } = require('uuid');
const { hasPermission, PERMISSIONS, ROLES } = require('../server/authorization/permissions');

runMigrations();

test('Phase 9: Database setup', async (t) => {
  await t.test('organizations table exists', () => {
    const stmt = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='organizations'");
    assert.strictEqual(stmt.get().name, 'organizations');
  });

  await t.test('organization_members table exists', () => {
    const stmt = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='organization_members'");
    assert.strictEqual(stmt.get().name, 'organization_members');
  });

  await t.test('teams table exists', () => {
    const stmt = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='teams'");
    assert.strictEqual(stmt.get().name, 'teams');
  });
});

test('Phase 9: RBAC Permissions', async (t) => {
  await t.test('Owner has all permissions', () => {
    assert.ok(hasPermission(ROLES.OWNER, PERMISSIONS.ORG_DELETE));
    assert.ok(hasPermission(ROLES.OWNER, PERMISSIONS.MEMBERS_INVITE));
  });

  await t.test('Admin cannot delete org', () => {
    assert.strictEqual(hasPermission(ROLES.ADMIN, PERMISSIONS.ORG_DELETE), false);
    assert.ok(hasPermission(ROLES.ADMIN, PERMISSIONS.MEMBERS_INVITE));
  });

  await t.test('Member cannot invite', () => {
    assert.strictEqual(hasPermission(ROLES.MEMBER, PERMISSIONS.MEMBERS_INVITE), false);
    assert.ok(hasPermission(ROLES.MEMBER, PERMISSIONS.TEAMS_READ));
  });
});

test('Phase 9: DB Constraints', async (t) => {
  const userId = uuidv4();
  db.prepare('INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)').run(userId, `orgowner_${uuidv4()}@example.com`, 'hash');

  const orgId = uuidv4();
  await t.test('Can create organization', () => {
    db.prepare(`
      INSERT INTO organizations (id, name, slug, owner_user_id)
      VALUES (?, ?, ?, ?)
    `).run(orgId, 'Test Org', `test-org-${uuidv4()}`, userId);
    
    const org = db.prepare('SELECT name FROM organizations WHERE id = ?').get(orgId);
    assert.strictEqual(org.name, 'Test Org');
  });

  await t.test('Can add member', () => {
    db.prepare(`
      INSERT INTO organization_members (id, organization_id, user_id, role)
      VALUES (?, ?, ?, ?)
    `).run(uuidv4(), orgId, userId, ROLES.OWNER);
    
    const count = db.prepare('SELECT COUNT(*) as c FROM organization_members WHERE organization_id = ?').get(orgId).c;
    assert.strictEqual(count, 1);
  });

  await t.test('Foreign key constraints', () => {
    assert.throws(() => {
      db.prepare(`
        INSERT INTO organization_members (id, organization_id, user_id, role)
        VALUES (?, ?, ?, ?)
      `).run(uuidv4(), 'fake-org', userId, ROLES.MEMBER);
    });
  });
});
