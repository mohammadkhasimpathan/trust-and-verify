const https = require('https');

function vtRequest(path) {
  return new Promise((resolve, reject) => {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) return resolve({ provider: 'VirusTotal', status: 'NOT_CONFIGURED' });

    const options = {
      hostname: 'www.virustotal.com',
      port: 443,
      path: '/api/v3' + path,
      method: 'GET',
      headers: {
        'x-apikey': apiKey
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode === 401 || res.statusCode === 403) {
          return resolve({ provider: 'VirusTotal', status: 'AUTH_ERROR' });
        }
        if (res.statusCode === 404) {
          return resolve({ provider: 'VirusTotal', status: 'NOT_FOUND' });
        }
        if (res.statusCode === 429) {
          return resolve({ provider: 'VirusTotal', status: 'RATE_LIMITED' });
        }
        if (res.statusCode >= 500) {
          return resolve({ provider: 'VirusTotal', status: 'PROVIDER_ERROR' });
        }

        try {
          const json = JSON.parse(data);
          resolve({ provider: 'VirusTotal', status: 'FOUND', data: json.data });
        } catch (e) {
          resolve({ provider: 'VirusTotal', status: 'ERROR', message: 'Invalid JSON response' });
        }
      });
    });

    req.on('error', (e) => reject(e));
    req.end();
  });
}

function normalizeResult(res, type) {
  if (res.status !== 'FOUND') return res;
  
  const stats = res.data.attributes.last_analysis_stats || {};
  return {
    provider: 'VirusTotal',
    status: 'FOUND',
    reputation: {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0
    },
    metadata: {
      last_analysis_date: res.data.attributes.last_analysis_date
    }
  };
}

module.exports = {
  name: 'VirusTotal',
  analyzeUrl: async (url) => {
    // base64 url without padding
    const b64 = Buffer.from(url).toString('base64').replace(/=/g, '');
    const res = await vtRequest('/urls/' + b64);
    return normalizeResult(res, 'URL');
  },
  analyzeDomain: async (domain) => {
    const res = await vtRequest('/domains/' + domain);
    return normalizeResult(res, 'DOMAIN');
  },
  analyzeHash: async (hash) => {
    const res = await vtRequest('/files/' + hash);
    return normalizeResult(res, 'HASH');
  }
};
