const db = require('../db/connection');
const { v4: uuidv4 } = require('uuid');

function logSecurityEvent(userId, eventType, success, req, metadata = {}) {
  try {
    const id = uuidv4();
    const ipMetadata = req ? req.ip || req.connection.remoteAddress : null;
    const userAgentMetadata = req ? req.headers['user-agent'] : null;

    // Sanitize metadata
    const safeMetadata = { ...metadata };
    delete safeMetadata.password;
    delete safeMetadata.token;
    delete safeMetadata.secret;
    delete safeMetadata.code;
    delete safeMetadata.cookie;

    db.prepare(`
      INSERT INTO security_events 
      (id, user_id, event_type, ip_metadata, user_agent_metadata, success, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      userId || null,
      eventType,
      ipMetadata,
      userAgentMetadata,
      success ? 1 : 0,
      JSON.stringify(safeMetadata)
    );
  } catch (err) {
    console.error('[SECURITY LOG ERROR]', err.message);
  }
}

function logOrganizationEvent(orgId, userId, eventType, req, metadata = {}) {
  try {
    const id = uuidv4();
    // Sanitize metadata
    const safeMetadata = { ...metadata };
    delete safeMetadata.password;
    delete safeMetadata.token;
    delete safeMetadata.secret;
    delete safeMetadata.code;

    db.prepare(`
      INSERT INTO organization_events 
      (id, organization_id, actor_user_id, event_type, metadata)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      id,
      orgId,
      userId || null,
      eventType,
      JSON.stringify(safeMetadata)
    );
  } catch (err) {
    console.error('[ORG LOG ERROR]', err.message);
  }
}

module.exports = {
  logSecurityEvent,
  logOrganizationEvent
};
