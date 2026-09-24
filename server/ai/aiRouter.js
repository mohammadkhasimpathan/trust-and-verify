const express = require('express');
const { requireOrganizationMembership, requirePermission } = require('../authorization/organizationAccess');
const { PERMISSIONS } = require('../authorization/permissions');
const { explainRisk } = require('./riskExplainer');
const { analyzeIncident } = require('./incidentAnalyst');
const { assistInvestigation } = require('./investigationAssistant');
const { generateHuntingQueries } = require('./threatHunter');
const { getAiSettings, updateAiSettings } = require('./aiSecurity');
const providerRegistry = require('./providerRegistry');

const router = express.Router({ mergeParams: true });

// Settings & Status
router.get('/status', requireOrganizationMembership, requirePermission(PERMISSIONS.AI_READ), async (req, res) => {
  try {
    const settings = getAiSettings(req.organizationId);
    if (!settings.enabled) {
      return res.json({ status: 'DISABLED' });
    }
    const provider = providerRegistry.getProvider(settings.provider);
    const health = await provider.healthCheck();
    res.json(health);
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/settings', requireOrganizationMembership, requirePermission(PERMISSIONS.AI_ADMIN), (req, res) => {
  try {
    updateAiSettings(req.organizationId, req.session.userId, req.body);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// Operations
router.post('/explain-risk', requireOrganizationMembership, requirePermission(PERMISSIONS.AI_USE), async (req, res) => {
  const result = await explainRisk(req.organizationId, req.session.userId, req.body.riskResult);
  res.json(result);
});

router.post('/analyze-incident', requireOrganizationMembership, requirePermission(PERMISSIONS.AI_INCIDENTS_ANALYZE), async (req, res) => {
  const result = await analyzeIncident(req.organizationId, req.session.userId, req.body.incidentData);
  res.json(result);
});

router.post('/assist-investigation', requireOrganizationMembership, requirePermission(PERMISSIONS.AI_INVESTIGATIONS_ASSIST), async (req, res) => {
  const result = await assistInvestigation(req.organizationId, req.session.userId, req.body.investigationData);
  res.json(result);
});

router.post('/hunt', requireOrganizationMembership, requirePermission(PERMISSIONS.AI_THREAT_HUNTING_USE), async (req, res) => {
  const result = await generateHuntingQueries(req.organizationId, req.session.userId, req.body.threatContext);
  res.json(result);
});

module.exports = router;
