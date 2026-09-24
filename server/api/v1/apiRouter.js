const express = require('express');
const { verifyApiKey } = require('../../integrations/integrationRegistry');

const router = express.Router();

// Middleware to authenticate via API key
router.use((req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer tvk_live_')) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Missing or invalid API key' } });
  }
  
  const token = authHeader.split(' ')[1];
  const apiKeyInfo = verifyApiKey(token);
  if (!apiKeyInfo) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid API key' } });
  }

  req.organizationId = apiKeyInfo.organizationId;
  req.scopes = apiKeyInfo.scopes;
  next();
});

// Middleware to check scopes
function requireScope(scope) {
  return (req, res, next) => {
    if (req.scopes.includes(scope) || req.scopes.includes('api.access')) {
      next();
    } else {
      res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Insufficient scope' } });
    }
  };
}

// Minimal v1 endpoints for Phase 11
router.get('/health', (req, res) => {
  res.json({ status: 'OK', version: 'v1' });
});

router.get('/incidents', requireScope('security.read'), (req, res) => {
  // Mock pagination response for incidents
  res.json({
    data: [],
    pagination: { page: 1, limit: 50, total: 0 }
  });
});

// Phase 12 AI Endpoints
const { explainRisk } = require('../../ai/riskExplainer');
const { analyzeIncident } = require('../../ai/incidentAnalyst');
const { assistInvestigation } = require('../../ai/investigationAssistant');
const { generateHuntingQueries } = require('../../ai/threatHunter');
const { summarizeReport } = require('../../ai/reportAssistant');
const { getAiSettings } = require('../../ai/aiSecurity');
const providerRegistry = require('../../ai/providerRegistry');

router.get('/ai/status', requireScope('ai.read'), async (req, res) => {
  try {
    const settings = getAiSettings(req.organizationId);
    if (!settings.enabled) return res.json({ status: 'DISABLED' });
    const provider = providerRegistry.getProvider(settings.provider);
    const health = await provider.healthCheck();
    res.json(health);
  } catch(err) { res.status(500).json({ error: 'Internal error' }); }
});

router.post('/ai/explain-risk', requireScope('ai.use'), async (req, res) => {
  const result = await explainRisk(req.organizationId, req.serviceAccountId || 'API_KEY', req.body.riskResult);
  res.json(result);
});

router.post('/ai/analyze-incident', requireScope('ai.incidents.analyze'), async (req, res) => {
  const result = await analyzeIncident(req.organizationId, req.serviceAccountId || 'API_KEY', req.body.incidentData);
  res.json(result);
});

router.post('/ai/assist-investigation', requireScope('ai.investigations.assist'), async (req, res) => {
  const result = await assistInvestigation(req.organizationId, req.serviceAccountId || 'API_KEY', req.body.investigationData);
  res.json(result);
});

router.post('/ai/hunt', requireScope('ai.threat_hunting.use'), async (req, res) => {
  const result = await generateHuntingQueries(req.organizationId, req.serviceAccountId || 'API_KEY', req.body.threatContext);
  res.json(result);
});

router.post('/ai/summarize', requireScope('ai.reports.generate'), async (req, res) => {
  const result = await summarizeReport(req.organizationId, req.serviceAccountId || 'API_KEY', req.body.reportData);
  res.json(result);
});

module.exports = router;
