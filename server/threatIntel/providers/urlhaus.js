const https = require('https');
const querystring = require('querystring');

module.exports = {
  name: 'URLhaus',
  analyzeUrl: async (url) => {
    return new Promise((resolve, reject) => {
      const postData = querystring.stringify({ url: url });
      
      const options = {
        hostname: 'urlhaus-api.abuse.ch',
        port: 443,
        path: '/v1/url/',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(postData)
        }
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode === 429) return resolve({ provider: 'URLhaus', status: 'RATE_LIMITED' });
          if (res.statusCode >= 500) return resolve({ provider: 'URLhaus', status: 'PROVIDER_ERROR' });

          try {
            const json = JSON.parse(data);
            if (json.query_status === 'ok') {
              resolve({ provider: 'URLhaus', status: 'FOUND', metadata: json });
            } else if (json.query_status === 'no_results') {
              resolve({ provider: 'URLhaus', status: 'NO_MATCH' });
            } else {
              resolve({ provider: 'URLhaus', status: 'ERROR', message: json.query_status });
            }
          } catch (e) {
            resolve({ provider: 'URLhaus', status: 'ERROR', message: 'Invalid JSON response' });
          }
        });
      });

      req.on('error', (e) => reject(e));
      req.write(postData);
      req.end();
    });
  },
  analyzeDomain: async () => ({ provider: 'URLhaus', status: 'NOT_SUPPORTED' }),
  analyzeHash: async () => ({ provider: 'URLhaus', status: 'NOT_SUPPORTED' })
};
