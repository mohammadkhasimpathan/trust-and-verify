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

module.exports = router;
