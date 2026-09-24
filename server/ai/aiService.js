const crypto = require('crypto');
const providerRegistry = require('./providerRegistry');
const { getPromptTemplate } = require('./promptManager');
const { buildContext } = require('./contextBuilder');
const { validateResponse } = require('./responseValidator');
const { logAiAudit } = require('./aiAuditLogger');
const { getAiSettings } = require('./aiSecurity');

async function processAiRequest(orgId, userId, operation, data, untrustedContext = null) {
  const start = Date.now();
  const settings = getAiSettings(orgId);

  if (!settings.enabled) {
    return { status: 'DISABLED', reason: 'AI is disabled for this organization' };
  }

  const provider = providerRegistry.getProvider(settings.provider);
  
  const instruction = getPromptTemplate(operation);
  const context = buildContext(data, { untrustedContext });
  
  const fullPrompt = `${instruction}\n${context}`;
  const inputFingerprint = crypto.createHash('sha256').update(fullPrompt).digest('hex');

  let response;
  try {
    const rawResponse = await provider.analyze(fullPrompt, { model: settings.model });
    response = validateResponse(rawResponse, 'json');
  } catch (err) {
    response = { status: 'ERROR', reason: err.message };
  }

  const durationMs = Date.now() - start;

  logAiAudit(
    orgId,
    userId,
    settings.provider,
    settings.model || 'default',
    operation,
    inputFingerprint,
    response.tokens || 0,
    'REDACTED',
    response.status,
    durationMs
  );

  return response;
}

module.exports = {
  processAiRequest
};
