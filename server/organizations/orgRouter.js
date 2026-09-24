const express = require('express');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const db = require('../db/connection');
const { requireAuth } = require('../auth/authMiddleware');
const { requireOrganizationMembership, requirePermission } = require('../authorization/organizationAccess');
const { PERMISSIONS, ROLES } = require('../authorization/permissions');
const { logOrganizationEvent } = require('../security/securityLogger');
const { sendEmail } = require('../email/emailService');

const router = express.Router();

function slugify(text) {
  return text.toString().toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^\w\-]+/g, '')
    .replace(/\-\-+/g, '-')
    .replace(/^-+/, '')
    .replace(/-+$/, '');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// ─── ORGANIZATIONS ─────────────────────────────────────────────────────

router.get('/', requireAuth, (req, res) => {
  try {
    const orgs = db.prepare(`
      SELECT o.id, o.name, o.slug, o.status, m.role
      FROM organizations o
      JOIN organization_members m ON o.id = m.organization_id
      WHERE m.user_id = ? AND m.status = 'ACTIVE'
    `).all(req.session.userId);
    res.json({ success: true, organizations: orgs });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/', requireAuth, (req, res) => {
  const { name } = req.body;
  if (!name || name.trim().length < 3) return res.status(400).json({ error: 'Invalid name' });

  const userId = req.session.userId;
  const orgId = uuidv4();
  const baseSlug = slugify(name);
  let slug = baseSlug;
  
  try {
    // Basic unique slug generation
    let count = 1;
    while (db.prepare('SELECT id FROM organizations WHERE slug = ?').get(slug)) {
      slug = `${baseSlug}-${count++}`;
    }

    db.transaction(() => {
      db.prepare(`
        INSERT INTO organizations (id, name, slug, owner_user_id)
        VALUES (?, ?, ?, ?)
      `).run(orgId, name, slug, userId);

      db.prepare(`
        INSERT INTO organization_members (id, organization_id, user_id, role)
        VALUES (?, ?, ?, ?)
      `).run(uuidv4(), orgId, userId, ROLES.OWNER);
    })();

    logOrganizationEvent(orgId, userId, 'ORGANIZATION_CREATED', req, { name, slug });
    res.json({ success: true, organizationId: orgId, slug });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.get('/:organizationId', requireOrganizationMembership, (req, res) => {
  try {
    const org = db.prepare('SELECT id, name, slug, owner_user_id, status, created_at FROM organizations WHERE id = ?').get(req.organizationId);
    // Include member count, team count
    const memberCount = db.prepare('SELECT COUNT(*) as count FROM organization_members WHERE organization_id = ?').get(req.organizationId).count;
    const teamCount = db.prepare('SELECT COUNT(*) as count FROM teams WHERE organization_id = ?').get(req.organizationId).count;
    
    res.json({
      success: true,
      organization: { ...org, memberCount, teamCount, userRole: req.organizationRole }
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.patch('/:organizationId', requireOrganizationMembership, requirePermission(PERMISSIONS.ORG_UPDATE), (req, res) => {
  const { name } = req.body;
  if (!name || name.trim().length < 3) return res.status(400).json({ error: 'Invalid name' });

  try {
    db.prepare('UPDATE organizations SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(name, req.organizationId);
    logOrganizationEvent(req.organizationId, req.session.userId, 'ORGANIZATION_UPDATED', req, { name });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.delete('/:organizationId', requireOrganizationMembership, requirePermission(PERMISSIONS.ORG_DELETE), (req, res) => {
  try {
    // Check if the user is the actual owner for strict deletion check
    const org = db.prepare('SELECT owner_user_id FROM organizations WHERE id = ?').get(req.organizationId);
    if (org.owner_user_id !== req.session.userId) {
      return res.status(403).json({ error: 'Only the organization owner can delete it.' });
    }

    db.transaction(() => {
      // Due to CASCADE, deleting the org will delete members, teams, etc.
      db.prepare('DELETE FROM organizations WHERE id = ?').run(req.organizationId);
    })();
    
    // We log to a null orgId or just rely on server logs since the org is gone.
    res.json({ success: true, message: 'Organization deleted.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ─── MEMBERS ───────────────────────────────────────────────────────────

router.get('/:organizationId/members', requireOrganizationMembership, requirePermission(PERMISSIONS.MEMBERS_READ), (req, res) => {
  try {
    const members = db.prepare(`
      SELECT m.id, m.user_id, m.role, m.status, m.joined_at, u.email, p.display_name
      FROM organization_members m
      JOIN users u ON m.user_id = u.id
      JOIN user_profiles p ON u.id = p.user_id
      WHERE m.organization_id = ?
    `).all(req.organizationId);
    res.json({ success: true, members });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.patch('/:organizationId/members/:memberId', requireOrganizationMembership, requirePermission(PERMISSIONS.MEMBERS_UPDATE), (req, res) => {
  const { role } = req.body;
  const { memberId } = req.params;
  
  if (!Object.values(ROLES).includes(role)) {
    return res.status(400).json({ error: 'Invalid role.' });
  }
  
  try {
    const member = db.prepare('SELECT user_id, role FROM organization_members WHERE id = ? AND organization_id = ?').get(memberId, req.organizationId);
    if (!member) return res.status(404).json({ error: 'Member not found.' });
    
    if (member.role === ROLES.OWNER || role === ROLES.OWNER) {
      return res.status(403).json({ error: 'Cannot change owner role through this endpoint. Use ownership transfer.' });
    }
    
    db.prepare('UPDATE organization_members SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(role, memberId);
    logOrganizationEvent(req.organizationId, req.session.userId, 'MEMBER_ROLE_CHANGED', req, { targetUserId: member.user_id, newRole: role });
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.delete('/:organizationId/members/:memberId', requireOrganizationMembership, requirePermission(PERMISSIONS.MEMBERS_REMOVE), (req, res) => {
  const { memberId } = req.params;
  
  try {
    const member = db.prepare('SELECT user_id, role FROM organization_members WHERE id = ? AND organization_id = ?').get(memberId, req.organizationId);
    if (!member) return res.status(404).json({ error: 'Member not found.' });
    
    if (member.role === ROLES.OWNER) {
      return res.status(403).json({ error: 'Cannot remove the owner.' });
    }
    
    db.transaction(() => {
      // Remove from teams
      db.prepare(`
        DELETE FROM team_members 
        WHERE user_id = ? AND team_id IN (SELECT id FROM teams WHERE organization_id = ?)
      `).run(member.user_id, req.organizationId);
      
      db.prepare('DELETE FROM organization_members WHERE id = ?').run(memberId);
    })();
    
    logOrganizationEvent(req.organizationId, req.session.userId, 'MEMBER_REMOVED', req, { targetUserId: member.user_id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// ─── OWNERSHIP TRANSFER ───────────────────────────────────────────────

router.post('/:organizationId/transfer-ownership', requireOrganizationMembership, (req, res) => {
  const { newOwnerUserId } = req.body;
  if (!newOwnerUserId) return res.status(400).json({ error: 'New owner user ID required.' });
  
  try {
    const org = db.prepare('SELECT owner_user_id FROM organizations WHERE id = ?').get(req.organizationId);
    if (org.owner_user_id !== req.session.userId) {
      return res.status(403).json({ error: 'Only current owner can transfer ownership.' });
    }
    
    const targetMember = db.prepare('SELECT id FROM organization_members WHERE organization_id = ? AND user_id = ?').get(req.organizationId, newOwnerUserId);
    if (!targetMember) return res.status(400).json({ error: 'Target user is not a member of the organization.' });
    
    db.transaction(() => {
      // Downgrade current owner to Admin
      db.prepare('UPDATE organization_members SET role = ? WHERE organization_id = ? AND user_id = ?').run(ROLES.ADMIN, req.organizationId, req.session.userId);
      // Upgrade new owner
      db.prepare('UPDATE organization_members SET role = ? WHERE organization_id = ? AND user_id = ?').run(ROLES.OWNER, req.organizationId, newOwnerUserId);
      // Update org owner
      db.prepare('UPDATE organizations SET owner_user_id = ? WHERE id = ?').run(newOwnerUserId, req.organizationId);
    })();
    
    logOrganizationEvent(req.organizationId, req.session.userId, 'OWNERSHIP_TRANSFERRED', req, { newOwnerUserId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// ─── TEAMS ─────────────────────────────────────────────────────────────

router.get('/:organizationId/teams', requireOrganizationMembership, requirePermission(PERMISSIONS.TEAMS_READ), (req, res) => {
  try {
    const teams = db.prepare('SELECT id, name, description, created_at FROM teams WHERE organization_id = ?').all(req.organizationId);
    for (const t of teams) {
      t.memberCount = db.prepare('SELECT COUNT(*) as count FROM team_members WHERE team_id = ?').get(t.id).count;
    }
    res.json({ success: true, teams });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/:organizationId/teams', requireOrganizationMembership, requirePermission(PERMISSIONS.TEAMS_CREATE), (req, res) => {
  const { name, description } = req.body;
  if (!name || name.trim().length < 2) return res.status(400).json({ error: 'Invalid name.' });
  
  const teamId = uuidv4();
  try {
    db.prepare(`
      INSERT INTO teams (id, organization_id, name, description, created_by)
      VALUES (?, ?, ?, ?, ?)
    `).run(teamId, req.organizationId, name, description, req.session.userId);
    
    logOrganizationEvent(req.organizationId, req.session.userId, 'TEAM_CREATED', req, { teamId, name });
    res.json({ success: true, teamId });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.delete('/:organizationId/teams/:teamId', requireOrganizationMembership, requirePermission(PERMISSIONS.TEAMS_DELETE), (req, res) => {
  const { teamId } = req.params;
  try {
    const team = db.prepare('SELECT id FROM teams WHERE id = ? AND organization_id = ?').get(teamId, req.organizationId);
    if (!team) return res.status(404).json({ error: 'Team not found.' });
    
    db.prepare('DELETE FROM teams WHERE id = ?').run(teamId); // Cascades team_members
    logOrganizationEvent(req.organizationId, req.session.userId, 'TEAM_DELETED', req, { teamId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/:organizationId/teams/:teamId/members', requireOrganizationMembership, requirePermission(PERMISSIONS.TEAMS_MANAGE_MEMBERS), (req, res) => {
  const { teamId } = req.params;
  const { userId } = req.body;
  
  try {
    const team = db.prepare('SELECT id FROM teams WHERE id = ? AND organization_id = ?').get(teamId, req.organizationId);
    if (!team) return res.status(404).json({ error: 'Team not found.' });
    
    const member = db.prepare('SELECT id FROM organization_members WHERE organization_id = ? AND user_id = ?').get(req.organizationId, userId);
    if (!member) return res.status(400).json({ error: 'User is not in the organization.' });
    
    db.prepare('INSERT OR IGNORE INTO team_members (id, team_id, user_id) VALUES (?, ?, ?)').run(uuidv4(), teamId, userId);
    logOrganizationEvent(req.organizationId, req.session.userId, 'TEAM_MEMBER_ADDED', req, { teamId, targetUserId: userId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.delete('/:organizationId/teams/:teamId/members/:userId', requireOrganizationMembership, requirePermission(PERMISSIONS.TEAMS_MANAGE_MEMBERS), (req, res) => {
  const { teamId, userId } = req.params;
  
  try {
    const team = db.prepare('SELECT id FROM teams WHERE id = ? AND organization_id = ?').get(teamId, req.organizationId);
    if (!team) return res.status(404).json({ error: 'Team not found.' });
    
    db.prepare('DELETE FROM team_members WHERE team_id = ? AND user_id = ?').run(teamId, userId);
    logOrganizationEvent(req.organizationId, req.session.userId, 'TEAM_MEMBER_REMOVED', req, { teamId, targetUserId: userId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// ─── INVITATIONS ───────────────────────────────────────────────────────

router.get('/:organizationId/invitations', requireOrganizationMembership, requirePermission(PERMISSIONS.MEMBERS_READ), (req, res) => {
  try {
    const invites = db.prepare('SELECT id, email, role, expires_at, created_at FROM organization_invitations WHERE organization_id = ? AND accepted_at IS NULL').all(req.organizationId);
    res.json({ success: true, invitations: invites });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/:organizationId/invitations', requireOrganizationMembership, requirePermission(PERMISSIONS.MEMBERS_INVITE), async (req, res) => {
  const { email, role } = req.body;
  if (!email || !Object.values(ROLES).includes(role)) return res.status(400).json({ error: 'Invalid input.' });
  if (role === ROLES.OWNER) return res.status(403).json({ error: 'Cannot invite an Owner.' });

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(rawToken);
    const inviteId = uuidv4();
    
    db.prepare(`
      INSERT INTO organization_invitations (id, organization_id, email, role, token_hash, invited_by, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now', '+7 days'))
    `).run(inviteId, req.organizationId, normalizedEmail, role, tokenHash, req.session.userId);
    
    const org = db.prepare('SELECT name FROM organizations WHERE id = ?').get(req.organizationId);
    
    const inviteUrl = `${req.protocol}://${req.get('host')}/accept-invite?token=${rawToken}`;
    
    await sendEmail({
      to: normalizedEmail,
      subject: `Invitation to join ${org.name} on Trust & Verify`,
      text: `You have been invited to join ${org.name}. Accept here: ${inviteUrl}`
    });
    
    logOrganizationEvent(req.organizationId, req.session.userId, 'MEMBER_INVITED', req, { email: normalizedEmail, role });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.delete('/:organizationId/invitations/:inviteId', requireOrganizationMembership, requirePermission(PERMISSIONS.MEMBERS_INVITE), (req, res) => {
  try {
    db.prepare('DELETE FROM organization_invitations WHERE id = ? AND organization_id = ?').run(req.params.inviteId, req.organizationId);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// Global accept invite route (does not require predefined org membership, but does require auth)
router.post('/accept-invite', requireAuth, (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required.' });
  
  try {
    const tokenHash = hashToken(token);
    const invite = db.prepare(`
      SELECT * FROM organization_invitations 
      WHERE token_hash = ? AND accepted_at IS NULL AND expires_at > datetime('now')
    `).get(tokenHash);
    
    if (!invite) return res.status(400).json({ error: 'Invalid or expired invitation.' });
    
    const user = db.prepare('SELECT email FROM users WHERE id = ?').get(req.session.userId);
    if (user.email !== invite.email) {
      return res.status(403).json({ error: 'This invitation was sent to a different email address.' });
    }
    
    db.transaction(() => {
      db.prepare('UPDATE organization_invitations SET accepted_at = CURRENT_TIMESTAMP WHERE id = ?').run(invite.id);
      db.prepare('INSERT OR IGNORE INTO organization_members (id, organization_id, user_id, role) VALUES (?, ?, ?, ?)').run(uuidv4(), invite.organization_id, req.session.userId, invite.role);
    })();
    
    logOrganizationEvent(invite.organization_id, req.session.userId, 'MEMBER_JOINED', req, { role: invite.role });
    res.json({ success: true, organizationId: invite.organization_id });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// ─── AUDIT LOGS ────────────────────────────────────────────────────────

router.get('/:organizationId/audit-log', requireOrganizationMembership, requirePermission(PERMISSIONS.AUDIT_READ), (req, res) => {
  try {
    const events = db.prepare(`
      SELECT e.id, e.event_type, e.created_at, e.metadata, p.display_name as actor_name, u.email as actor_email
      FROM organization_events e
      LEFT JOIN users u ON e.actor_user_id = u.id
      LEFT JOIN user_profiles p ON u.id = p.user_id
      WHERE e.organization_id = ?
      ORDER BY e.created_at DESC
      LIMIT 100
    `).all(req.organizationId);
    
    res.json({ success: true, events: events.map(e => ({...e, metadata: JSON.parse(e.metadata || '{}')})) });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

module.exports = router;
