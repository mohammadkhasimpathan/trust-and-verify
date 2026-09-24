const db = require('../db/connection');
const { v4: uuidv4 } = require('uuid');

function dispatchEvent(orgId, eventType, payload) {
  // Store event in webhook_deliveries for any matching webhook
  const webhooks = db.prepare('SELECT id, events, secret_hash FROM webhook_endpoints WHERE organization_id = ? AND status = "ACTIVE"').all(orgId);
  
  for (const hook of webhooks) {
    const subscribedEvents = JSON.parse(hook.events || '[]');
    if (subscribedEvents.includes(eventType) || subscribedEvents.includes('*')) {
      const deliveryId = uuidv4();
      const eventId = uuidv4();
      
      db.prepare(`
        INSERT INTO webhook_deliveries (id, organization_id, webhook_id, event_id, event_type, payload)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(deliveryId, orgId, hook.id, eventId, eventType, JSON.stringify(payload));
    }
  }

  // SIEM/SOAR/Notifications could also hook in here and create outbound deliveries
  // For Phase 11, we are using the outbox pattern via webhook_deliveries or similar 
  // queue tables.
}

module.exports = {
  dispatchEvent
};
