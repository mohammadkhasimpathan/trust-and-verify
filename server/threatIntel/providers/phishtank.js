const https = require('https');
const querystring = require('querystring');

module.exports = {
  name: 'PhishTank',
  analyzeUrl: async (url) => {
    return new Promise((resolve, reject) => {
      const apiKey = process.env.PHISHTANK_API_KEY; // Optional but good for rate limits
      
      const postData = querystring.stringify({
        url: url,
        format: 'json',
        app_key: apiKey || ''
      });

      const options = {
        hostname: 'checkurl.phishtank.com',
        port: 443,
        path: '/checkurl/',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(postData),
          'User-Agent': 'trust-verify/1.0'
        }
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode === 509 || res.statusCode === 429) return resolve({ provider: 'PhishTank', status: 'RATE_LIMITED' });
          if (res.statusCode >= 500) return resolve({ provider: 'PhishTank', status: 'PROVIDER_ERROR' });

          try {
            const json = JSON.parse(data);
            if (json.results && json.results.in_database) {
              if (json.results.valid) {
                resolve({ provider: 'PhishTank', status: 'FOUND', metadata: json.results });
              } else {
                resolve({ provider: 'PhishTank', status: 'NO_MATCH', message: 'Found but marked invalid' });
              }
            } else {
              resolve({ provider: 'PhishTank', status: 'NO_MATCH' });
            }
          } catch (e) {
            resolve({ provider: 'PhishTank', status: 'ERROR', message: 'Invalid JSON response' });
          }
        });
      });

      req.on('error', (e) => reject(e));
      req.write(postData);
      req.end();
    });
  },
  analyzeDomain: async () => ({ provider: 'PhishTank', status: 'NOT_SUPPORTED' }),
  analyzeHash: async () => ({ provider: 'PhishTank', status: 'NOT_SUPPORTED' })
};
