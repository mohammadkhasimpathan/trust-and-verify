const db = require('../db/connection');
const { v4: uuidv4 } = require('uuid');

function logAiAudit(orgId, userId, provider, model, operation, inputFingerprint, tokenUsage, redactionStatus, status, durationMs) {
  const id = uuidv4();
  db.prepare(`
    INSERT INTO ai_audit_logs (id, organization_id, user_id, provider, model, operation, input_fingerprint, token_usage, redaction_status, status, duration_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, orgId, userId, provider, model, operation, inputFingerprint, tokenUsage, redactionStatus, status, durationMs);
  return id;
}

module.exports = {
  logAiAudit
};
