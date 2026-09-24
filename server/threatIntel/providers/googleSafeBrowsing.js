const https = require('https');

module.exports = {
  name: 'Google Safe Browsing',
  analyzeUrl: async (url) => {
    return new Promise((resolve, reject) => {
      const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
      if (!apiKey) return resolve({ provider: 'Google Safe Browsing', status: 'NOT_CONFIGURED' });

      const postData = JSON.stringify({
        client: { clientId: 'trust-verify', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      });

      const options = {
        hostname: 'safebrowsing.googleapis.com',
        port: 443,
        path: '/v4/threatMatches:find?key=' + apiKey,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        }
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode === 400) return resolve({ provider: 'Google Safe Browsing', status: 'INVALID_REQUEST' });
          if (res.statusCode === 403) return resolve({ provider: 'Google Safe Browsing', status: 'AUTH_ERROR' });
          if (res.statusCode === 429) return resolve({ provider: 'Google Safe Browsing', status: 'RATE_LIMITED' });
          if (res.statusCode >= 500) return resolve({ provider: 'Google Safe Browsing', status: 'PROVIDER_ERROR' });

          try {
            const json = JSON.parse(data);
            if (json.matches && json.matches.length > 0) {
              resolve({
                provider: 'Google Safe Browsing',
                status: 'FOUND',
                detections: json.matches.map(m => ({
                  threatType: m.threatType,
                  platformType: m.platformType,
                  threatEntryType: m.threatEntryType
                }))
              });
            } else {
              resolve({ provider: 'Google Safe Browsing', status: 'NO_MATCH' });
            }
          } catch (e) {
            resolve({ provider: 'Google Safe Browsing', status: 'ERROR', message: 'Invalid JSON response' });
          }
        });
      });

      req.on('error', (e) => reject(e));
      req.write(postData);
      req.end();
    });
  },
  analyzeDomain: async (domain) => {
    return { provider: 'Google Safe Browsing', status: 'NOT_SUPPORTED' };
  },
  analyzeHash: async (hash) => {
    return { provider: 'Google Safe Browsing', status: 'NOT_SUPPORTED' };
  }
};
