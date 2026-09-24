const db = require('../db/connection');

function getAiSettings(orgId) {
  const settings = db.prepare('SELECT * FROM ai_settings WHERE organization_id = ?').get(orgId);
  if (!settings) {
    return { enabled: false, provider: 'LOCAL', data_sharing_policy: 'STRICT' };
  }
  return {
    enabled: settings.enabled === 1,
    provider: settings.provider,
    model: settings.model,
    data_sharing_policy: settings.data_sharing_policy
  };
}

function updateAiSettings(orgId, userId, settings) {
  db.prepare(`
    INSERT INTO ai_settings (organization_id, enabled, provider, model, data_sharing_policy, updated_by)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(organization_id) DO UPDATE SET
      enabled = excluded.enabled,
      provider = excluded.provider,
      model = excluded.model,
      data_sharing_policy = excluded.data_sharing_policy,
      updated_by = excluded.updated_by,
      updated_at = CURRENT_TIMESTAMP
  `).run(
    orgId,
    settings.enabled ? 1 : 0,
    settings.provider || 'LOCAL',
    settings.model || null,
    settings.data_sharing_policy || 'STRICT',
    userId
  );
}

module.exports = {
  getAiSettings,
  updateAiSettings
};
