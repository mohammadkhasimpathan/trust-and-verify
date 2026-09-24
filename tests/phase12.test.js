const test = require('node:test');
const assert = require('node:assert');
const { processAiRequest } = require('../server/ai/aiService');
const { getAiSettings, updateAiSettings } = require('../server/ai/aiSecurity');
const { redactSensitiveData } = require('../server/ai/redaction');
const { explainRisk } = require('../server/ai/riskExplainer');
const db = require('../server/db/connection');
const crypto = require('crypto');

test('Phase 12: AI Redaction', async (t) => {
  await t.test('Redacts passwords', () => {
    const raw = 'my password="SuperSecretPassword" is here';
    const redacted = redactSensitiveData(raw);
    assert.match(redacted, /<REDACTED>/);
    assert.doesNotMatch(redacted, /SuperSecretPassword/);
  });

  await t.test('Redacts API keys', () => {
    const raw = 'api_key: "ak_live_12345"';
    const redacted = redactSensitiveData(raw);
    assert.match(redacted, /<REDACTED>/);
    assert.doesNotMatch(redacted, /ak_live_12345/);
  });
});

test('Phase 12: AI Service Status (Local & Unavailable)', async (t) => {
  // Create test org
  const orgId = crypto.randomUUID();
  const userId = crypto.randomUUID();
  
  const uniqueEmail = `ai_${crypto.randomUUID()}@example.com`;
  db.prepare('INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)').run(userId, uniqueEmail, 'hash');
  db.prepare('INSERT INTO organizations (id, name, slug, owner_user_id) VALUES (?, ?, ?, ?)').run(orgId, 'AI Org', 'ai-org-' + orgId, userId);

  await t.test('Returns DISABLED when AI is not enabled', async () => {
    const res = await processAiRequest(orgId, userId, 'RISK_EXPLAINER', { score: 90 });
    assert.strictEqual(res.status, 'DISABLED');
  });

  await t.test('Local Provider returns UNAVAILABLE for analysis when not running', async () => {
    updateAiSettings(orgId, userId, { enabled: true, provider: 'LOCAL' });
    const res = await processAiRequest(orgId, userId, 'RISK_EXPLAINER', { score: 90 });
    assert.strictEqual(res.status, 'UNAVAILABLE');
  });

  await t.test('OpenAI Provider returns UNAVAILABLE when API key is missing', async () => {
    updateAiSettings(orgId, userId, { enabled: true, provider: 'OPENAI_COMPATIBLE' });
    const res = await processAiRequest(orgId, userId, 'RISK_EXPLAINER', { score: 90 });
    assert.strictEqual(res.status, 'UNAVAILABLE');
  });
});
