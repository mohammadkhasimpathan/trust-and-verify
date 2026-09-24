const express = require('express');
const { requireOrganizationMembership, requirePermission } = require('../authorization/organizationAccess');
const { PERMISSIONS } = require('../authorization/permissions');
const { logOrganizationEvent } = require('../security/securityLogger');
const { createIntegration, getIntegrations, createApiKey, createServiceAccount } = require('./integrationRegistry');
const { createWebhook, getWebhooks } = require('./webhookService');

const router = express.Router({ mergeParams: true });

// Integrations
router.get('/', requireOrganizationMembership, requirePermission(PERMISSIONS.INTEGRATIONS_READ), (req, res) => {
  try {
    const list = getIntegrations(req.organizationId);
    res.json({ success: true, integrations: list });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/', requireOrganizationMembership, requirePermission(PERMISSIONS.INTEGRATIONS_CREATE), (req, res) => {
  const { type, name, provider, configuration, secret } = req.body;
  if (!type || !name || !provider) return res.status(400).json({ error: 'Missing required fields' });
  try {
    const id = createIntegration(req.organizationId, req.session.userId, type, name, provider, configuration, secret);
    logOrganizationEvent(req.organizationId, req.session.userId, 'INTEGRATION_CREATED', req, { integrationId: id, provider });
    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// Webhooks
router.get('/webhooks', requireOrganizationMembership, requirePermission(PERMISSIONS.WEBHOOKS_READ), (req, res) => {
  try {
    const list = getWebhooks(req.organizationId);
    res.json({ success: true, webhooks: list });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/webhooks', requireOrganizationMembership, requirePermission(PERMISSIONS.WEBHOOKS_CREATE), async (req, res) => {
  const { name, url, events } = req.body;
  try {
    const { id, secret } = await createWebhook(req.organizationId, req.session.userId, name, url, events);
    logOrganizationEvent(req.organizationId, req.session.userId, 'WEBHOOK_CREATED', req, { webhookId: id });
    res.json({ success: true, id, secret });
  } catch (err) {
    if (err.message === 'Invalid or unsafe webhook URL') return res.status(400).json({ error: err.message });
    res.status(500).json({ error: 'Internal error' });
  }
});

// API Keys
router.post('/apikeys', requireOrganizationMembership, requirePermission(PERMISSIONS.API_KEYS_CREATE), (req, res) => {
  const { name, scopes, serviceAccountId } = req.body;
  try {
    const result = createApiKey(req.organizationId, req.session.userId, serviceAccountId, name, scopes);
    logOrganizationEvent(req.organizationId, req.session.userId, 'API_KEY_CREATED', req, { apiKeyId: result.id });
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// Service Accounts
router.post('/serviceaccounts', requireOrganizationMembership, requirePermission(PERMISSIONS.SERVICE_ACCOUNTS_CREATE), (req, res) => {
  const { name, description } = req.body;
  try {
    const id = createServiceAccount(req.organizationId, req.session.userId, name, description);
    logOrganizationEvent(req.organizationId, req.session.userId, 'SERVICE_ACCOUNT_CREATED', req, { serviceAccountId: id });
    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

module.exports = router;
