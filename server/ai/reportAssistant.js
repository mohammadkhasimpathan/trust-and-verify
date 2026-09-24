const { processAiRequest } = require('./aiService');

async function summarizeReport(orgId, userId, reportData) {
  const response = await processAiRequest(orgId, userId, 'REPORT_ASSISTANT', reportData);
  if (response.status !== 'SUCCESS') {
    return { error: response.reason || 'AI unavailable' };
  }
  return {
    summary: response.text,
    aiConfidence: response.confidence
  };
}

module.exports = { summarizeReport };
