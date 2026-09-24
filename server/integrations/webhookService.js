const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/connection');
const dns = require('dns').promises;
const url = require('url');

async function isSafeUrl(targetUrl) {
  try {
    const parsed = new url.URL(targetUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;

    // Reject obvious local network hostnames
    if (parsed.hostname.toLowerCase() === 'localhost' || parsed.hostname.endsWith('.local') || parsed.hostname.endsWith('.internal')) {
      return false;
    }

    const ips = await dns.resolve4(parsed.hostname);
    if (!ips || ips.length === 0) return false;

    // Check if any IP is private/loopback
    for (const ip of ips) {
      const parts = ip.split('.').map(Number);
      if (parts[0] === 10) return false;
      if (parts[0] === 127) return false;
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
      if (parts[0] === 192 && parts[1] === 168) return false;
      if (parts[0] === 169 && parts[1] === 254) return false;
      if (parts[0] === 0) return false;
    }
    return true;
  } catch (err) {
    return false;
  }
}

async function createWebhook(orgId, userId, name, targetUrl, events) {
  if (!(await isSafeUrl(targetUrl))) {
    throw new Error('Invalid or unsafe webhook URL');
  }

  const id = uuidv4();
  const secret = crypto.randomBytes(32).toString('hex');
  const secretHash = crypto.createHash('sha256').update(secret).digest('hex');

  db.prepare(`
    INSERT INTO webhook_endpoints (id, organization_id, name, url, secret_hash, events, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, orgId, name, targetUrl, secretHash, JSON.stringify(events), userId);

  return { id, secret }; // Return secret only once
}

function getWebhooks(orgId) {
  return db.prepare('SELECT id, name, url, events, status FROM webhook_endpoints WHERE organization_id = ?').all(orgId);
}

function signPayload(payload, secretHash) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const dataToSign = timestamp + '.' + JSON.stringify(payload);
  const signature = crypto.createHmac('sha256', secretHash).update(dataToSign).digest('hex');
  return { timestamp, signature };
}

module.exports = {
  createWebhook,
  getWebhooks,
  signPayload,
  isSafeUrl
};
