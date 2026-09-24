const express = require('express');
const router = express.Router();
const config = require('./config');
const cache = require('./cache');

const providers = {
  virustotal: require('./providers/virustotal'),
  googleSafeBrowsing: require('./providers/googleSafeBrowsing'),
  phishtank: require('./providers/phishtank'),
  urlhaus: require('./providers/urlhaus')
};

// Utility to run a promise with a timeout
const withTimeout = (promise, ms) => {
  let timeoutId;
  const timeoutPromise = new Promise((resolve, reject) => {
    timeoutId = setTimeout(() => reject(new Error('TIMEOUT')), ms);
  });
  return Promise.race([promise, timeoutPromise]).finally(() => clearTimeout(timeoutId));
};

async function executeProviders(target, type) {
  const results = [];
  const promises = [];

  for (const [key, provider] of Object.entries(providers)) {
    if (!config.providers[key]) {
      results.push({ provider: provider.name || key, status: 'DISABLED' });
      continue;
    }

    const cacheKey = `${key}:${type}:${target}`;
    if (config.cache.enabled) {
      const cached = cache.get(cacheKey);
      if (cached) {
        results.push(cached);
        continue;
      }
    }

    let analyzeFn;
    if (type === 'URL') analyzeFn = provider.analyzeUrl;
    else if (type === 'DOMAIN') analyzeFn = provider.analyzeDomain;
    else if (type === 'HASH') analyzeFn = provider.analyzeHash;

    if (!analyzeFn) {
      results.push({ provider: provider.name || key, status: 'NOT_SUPPORTED' });
      continue;
    }

    const p = withTimeout(analyzeFn(target), config.timeouts.provider)
      .then(res => {
        if (config.cache.enabled && res.status !== 'ERROR' && res.status !== 'TIMEOUT') {
          cache.set(cacheKey, res, config.cache.ttlSecs);
        }
        return res;
      })
      .catch(err => {
        return {
          provider: provider.name || key,
          status: err.message === 'TIMEOUT' ? 'TIMEOUT' : 'ERROR',
          message: err.message
        };
      });

    promises.push(p);
  }

  // Wait for all providers, but impose an overall timeout on the Promise.allSettled
  const allSettled = await withTimeout(Promise.allSettled(promises), config.timeouts.overall).catch(() => []);
  
  allSettled.forEach(result => {
    if (result.status === 'fulfilled') {
      results.push(result.value);
    } else {
      // The overall timeout hit or something threw in the promise chain
      // If we don't have a result for a provider, it's missing, but we handle it gracefully
    }
  });

  return results;
}

router.post('/url', async (req, res) => {
  if (!config.enabled) return res.status(403).json({ error: 'Threat Intelligence is disabled globally.' });
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Missing target.' });
  
  try {
    const results = await executeProviders(target, 'URL');
    res.json({ target, type: 'URL', results });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

router.post('/domain', async (req, res) => {
  if (!config.enabled) return res.status(403).json({ error: 'Threat Intelligence is disabled globally.' });
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Missing target.' });
  
  try {
    const results = await executeProviders(target, 'DOMAIN');
    res.json({ target, type: 'DOMAIN', results });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

router.post('/hash', async (req, res) => {
  if (!config.enabled) return res.status(403).json({ error: 'Threat Intelligence is disabled globally.' });
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Missing target.' });
  
  try {
    const results = await executeProviders(target, 'HASH');
    res.json({ target, type: 'HASH', results });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;
module.exports.executeProviders = executeProviders;
