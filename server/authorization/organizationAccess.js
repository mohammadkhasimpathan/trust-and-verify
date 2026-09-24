// organizationAccess.js
const db = require('../db/connection');
const { hasPermission } = require('./permissions');

function requireOrganizationMembership(req, res, next) {
  const orgId = req.params.organizationId || req.body.organizationId;
  if (!orgId) return res.status(400).json({ error: 'Organization ID is required.' });
  
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Authentication required.' });
  }

  try {
    const member = db.prepare(`
      SELECT role, status 
      FROM organization_members 
      WHERE organization_id = ? AND user_id = ?
    `).get(orgId, req.session.userId);

    if (!member || member.status !== 'ACTIVE') {
      return res.status(403).json({ error: 'Access denied to this organization.' });
    }

    req.organizationId = orgId;
    req.organizationRole = member.role;
    next();
  } catch (err) {
    res.status(500).json({ error: 'Authorization error.' });
  }
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.organizationRole) {
      return res.status(500).json({ error: 'Role not loaded.' });
    }
    
    if (!hasPermission(req.organizationRole, permission)) {
      return res.status(403).json({ error: 'Insufficient permissions.' });
    }
    next();
  };
}

module.exports = {
  requireOrganizationMembership,
  requirePermission
};
