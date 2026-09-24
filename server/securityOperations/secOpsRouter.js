const express = require('express');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const db = require('../db/connection');
const { requireOrganizationMembership, requirePermission } = require('../authorization/organizationAccess');
const { PERMISSIONS } = require('../authorization/permissions');
const { logOrganizationEvent } = require('../security/securityLogger');
const { fetchThreatIntel } = require('../threatIntel/threatIntelClient');

const router = express.Router({ mergeParams: true });

function createFingerprint(type, normalizedValue) {
  return crypto.createHash('sha256').update(`${type}:${normalizedValue}`).digest('hex');
}

// ─── IOCs ──────────────────────────────────────────────────────────────

router.get('/iocs', requireOrganizationMembership, requirePermission(PERMISSIONS.IOCS_READ), (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    
    // basic sorting guard
    const iocs = db.prepare(`
      SELECT id, type, value, source, confidence, severity, status, first_seen, last_seen
      FROM indicators 
      WHERE organization_id = ?
      ORDER BY updated_at DESC
      LIMIT ? OFFSET ?
    `).all(req.organizationId, Math.min(limit, 100), offset);
    
    res.json({ success: true, iocs });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/iocs', requireOrganizationMembership, requirePermission(PERMISSIONS.IOCS_CREATE), (req, res) => {
  const { type, value, source, confidence, severity } = req.body;
  if (!type || !value) return res.status(400).json({ error: 'Type and value are required.' });
  
  const normalizedValue = value.trim().toLowerCase(); // Basic normalization
  const fingerprint = createFingerprint(type, normalizedValue);
  const id = uuidv4();
  
  try {
    db.prepare(`
      INSERT INTO indicators (id, organization_id, type, value, normalized_value, fingerprint, source, confidence, severity, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, req.organizationId, type, value, normalizedValue, fingerprint, source || 'USER_REPORTED', confidence || 0, severity || 'LOW', req.session.userId);
    
    logOrganizationEvent(req.organizationId, req.session.userId, 'IOC_CREATED', req, { iocId: id, type, value });
    res.json({ success: true, iocId: id });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(400).json({ error: 'IOC already exists in this organization.' });
    }
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/iocs/:id/enrich', requireOrganizationMembership, requirePermission(PERMISSIONS.IOCS_ENRICH), async (req, res) => {
  const { id } = req.params;
  try {
    const ioc = db.prepare('SELECT type, value FROM indicators WHERE id = ? AND organization_id = ?').get(id, req.organizationId);
    if (!ioc) return res.status(404).json({ error: 'IOC not found.' });

    let intelType;
    if (ioc.type === 'URL') intelType = 'url';
    else if (ioc.type === 'Domain') intelType = 'domain';
    else if (ioc.type === 'IPv4' || ioc.type === 'IPv6') intelType = 'ip';
    else if (ioc.type.includes('SHA') || ioc.type === 'MD5') intelType = 'hash';
    else return res.status(400).json({ error: 'Enrichment not supported for this IOC type.' });

    const results = await fetchThreatIntel(intelType, ioc.value);
    
    db.prepare('UPDATE indicators SET updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(id);
    logOrganizationEvent(req.organizationId, req.session.userId, 'IOC_ENRICHED', req, { iocId: id });
    
    res.json({ success: true, enrichment: results });
  } catch (err) {
    res.status(500).json({ error: 'Enrichment failed' });
  }
});

router.patch('/iocs/:id', requireOrganizationMembership, requirePermission(PERMISSIONS.IOCS_UPDATE), (req, res) => {
  const { status, severity, confidence } = req.body;
  const { id } = req.params;
  
  try {
    const ioc = db.prepare('SELECT id FROM indicators WHERE id = ? AND organization_id = ?').get(id, req.organizationId);
    if (!ioc) return res.status(404).json({ error: 'IOC not found.' });

    db.prepare(`
      UPDATE indicators SET status = ?, severity = ?, confidence = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(status, severity, confidence, id);
    
    logOrganizationEvent(req.organizationId, req.session.userId, 'IOC_UPDATED', req, { iocId: id, status, severity });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.delete('/iocs/:id', requireOrganizationMembership, requirePermission(PERMISSIONS.IOCS_DELETE), (req, res) => {
  const { id } = req.params;
  try {
    const ioc = db.prepare('SELECT id FROM indicators WHERE id = ? AND organization_id = ?').get(id, req.organizationId);
    if (!ioc) return res.status(404).json({ error: 'IOC not found.' });

    db.prepare('DELETE FROM indicators WHERE id = ?').run(id);
    logOrganizationEvent(req.organizationId, req.session.userId, 'IOC_DELETED', req, { iocId: id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// ─── INCIDENTS ─────────────────────────────────────────────────────────

router.get('/incidents', requireOrganizationMembership, requirePermission(PERMISSIONS.INCIDENTS_READ), (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    const incidents = db.prepare(`
      SELECT id, title, severity, status, category, created_at, updated_at, assigned_to
      FROM security_incidents 
      WHERE organization_id = ?
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).all(req.organizationId, Math.min(limit, 100), offset);
    
    res.json({ success: true, incidents });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/incidents', requireOrganizationMembership, requirePermission(PERMISSIONS.INCIDENTS_CREATE), (req, res) => {
  const { title, description, severity, category, source } = req.body;
  if (!title || !category || !severity) return res.status(400).json({ error: 'Title, category, and severity are required.' });
  
  const id = uuidv4();
  try {
    db.transaction(() => {
      db.prepare(`
        INSERT INTO security_incidents (id, organization_id, title, description, severity, category, source, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(id, req.organizationId, title, description, severity, category, source, req.session.userId);
      
      db.prepare(`
        INSERT INTO incident_events (id, incident_id, event_type, actor_user_id)
        VALUES (?, ?, 'INCIDENT_CREATED', ?)
      `).run(uuidv4(), id, req.session.userId);
    })();
    
    logOrganizationEvent(req.organizationId, req.session.userId, 'INCIDENT_CREATED', req, { incidentId: id, severity, category });
    res.json({ success: true, incidentId: id });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.get('/incidents/:id', requireOrganizationMembership, requirePermission(PERMISSIONS.INCIDENTS_READ), (req, res) => {
  const { id } = req.params;
  try {
    const incident = db.prepare('SELECT * FROM security_incidents WHERE id = ? AND organization_id = ?').get(id, req.organizationId);
    if (!incident) return res.status(404).json({ error: 'Incident not found.' });

    const events = db.prepare('SELECT * FROM incident_events WHERE incident_id = ? ORDER BY created_at ASC').all(id);
    const iocs = db.prepare(`
      SELECT i.* FROM indicators i 
      JOIN incident_iocs ii ON i.id = ii.ioc_id 
      WHERE ii.incident_id = ?
    `).all(id);

    res.json({ success: true, incident, events, iocs });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.patch('/incidents/:id', requireOrganizationMembership, requirePermission(PERMISSIONS.INCIDENTS_UPDATE), (req, res) => {
  const { id } = req.params;
  const { title, description, severity, status } = req.body;
  
  try {
    const incident = db.prepare('SELECT * FROM security_incidents WHERE id = ? AND organization_id = ?').get(id, req.organizationId);
    if (!incident) return res.status(404).json({ error: 'Incident not found.' });

    db.transaction(() => {
      db.prepare(`
        UPDATE security_incidents 
        SET title = COALESCE(?, title), description = COALESCE(?, description), severity = COALESCE(?, severity), status = COALESCE(?, status), updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(title, description, severity, status, id);
      
      if (status && status !== incident.status) {
        db.prepare('INSERT INTO incident_events (id, incident_id, event_type, actor_user_id, metadata) VALUES (?, ?, ?, ?, ?)')
          .run(uuidv4(), id, 'STATUS_CHANGED', req.session.userId, JSON.stringify({ old: incident.status, new: status }));
      }
      if (severity && severity !== incident.severity) {
        db.prepare('INSERT INTO incident_events (id, incident_id, event_type, actor_user_id, metadata) VALUES (?, ?, ?, ?, ?)')
          .run(uuidv4(), id, 'SEVERITY_CHANGED', req.session.userId, JSON.stringify({ old: incident.severity, new: severity }));
      }
    })();

    logOrganizationEvent(req.organizationId, req.session.userId, 'INCIDENT_UPDATED', req, { incidentId: id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/incidents/:id/assign', requireOrganizationMembership, requirePermission(PERMISSIONS.INCIDENTS_ASSIGN), (req, res) => {
  const { id } = req.params;
  const { userId } = req.body; // Can be null to unassign

  try {
    const incident = db.prepare('SELECT id FROM security_incidents WHERE id = ? AND organization_id = ?').get(id, req.organizationId);
    if (!incident) return res.status(404).json({ error: 'Incident not found.' });

    if (userId) {
      const member = db.prepare('SELECT id FROM organization_members WHERE organization_id = ? AND user_id = ?').get(req.organizationId, userId);
      if (!member) return res.status(400).json({ error: 'User is not a member of the organization.' });
    }

    db.transaction(() => {
      db.prepare('UPDATE security_incidents SET assigned_to = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(userId || null, id);
      db.prepare('INSERT INTO incident_events (id, incident_id, event_type, actor_user_id, metadata) VALUES (?, ?, ?, ?, ?)')
        .run(uuidv4(), id, userId ? 'ASSIGNED' : 'UNASSIGNED', req.session.userId, JSON.stringify({ assignedTo: userId }));
    })();

    logOrganizationEvent(req.organizationId, req.session.userId, 'INCIDENT_ASSIGNED', req, { incidentId: id, assignedTo: userId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/incidents/:id/close', requireOrganizationMembership, requirePermission(PERMISSIONS.INCIDENTS_CLOSE), (req, res) => {
  const { id } = req.params;
  try {
    const incident = db.prepare('SELECT id FROM security_incidents WHERE id = ? AND organization_id = ?').get(id, req.organizationId);
    if (!incident) return res.status(404).json({ error: 'Incident not found.' });

    db.transaction(() => {
      db.prepare("UPDATE security_incidents SET status = 'CLOSED', closed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(id);
      db.prepare('INSERT INTO incident_events (id, incident_id, event_type, actor_user_id) VALUES (?, ?, ?, ?)')
        .run(uuidv4(), id, 'INCIDENT_CLOSED', req.session.userId);
    })();

    logOrganizationEvent(req.organizationId, req.session.userId, 'INCIDENT_CLOSED', req, { incidentId: id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// ─── INVESTIGATIONS ────────────────────────────────────────────────────

router.post('/investigations', requireOrganizationMembership, requirePermission(PERMISSIONS.INVESTIGATIONS_CREATE), (req, res) => {
  const { title, description } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required.' });

  const id = uuidv4();
  try {
    db.prepare(`
      INSERT INTO investigations (id, organization_id, title, description, created_by)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, req.organizationId, title, description, req.session.userId);

    logOrganizationEvent(req.organizationId, req.session.userId, 'INVESTIGATION_CREATED', req, { investigationId: id });
    res.json({ success: true, investigationId: id });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.get('/investigations', requireOrganizationMembership, requirePermission(PERMISSIONS.INVESTIGATIONS_READ), (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    const investigations = db.prepare(`
      SELECT id, title, status, created_at, updated_at, assigned_to
      FROM investigations
      WHERE organization_id = ?
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).all(req.organizationId, Math.min(limit, 100), offset);
    res.json({ success: true, investigations });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/investigations/:id/close', requireOrganizationMembership, requirePermission(PERMISSIONS.INVESTIGATIONS_CLOSE), (req, res) => {
  const { id } = req.params;
  try {
    const inv = db.prepare('SELECT id FROM investigations WHERE id = ? AND organization_id = ?').get(id, req.organizationId);
    if (!inv) return res.status(404).json({ error: 'Investigation not found.' });

    db.prepare("UPDATE investigations SET status = 'CLOSED', closed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(id);
    logOrganizationEvent(req.organizationId, req.session.userId, 'INVESTIGATION_CLOSED', req, { investigationId: id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// ─── CAMPAIGNS ─────────────────────────────────────────────────────────

router.get('/campaigns', requireOrganizationMembership, requirePermission(PERMISSIONS.CAMPAIGNS_READ), (req, res) => {
  try {
    const campaigns = db.prepare(`
      SELECT id, name, type, status, created_at, started_at, ended_at
      FROM security_campaigns
      WHERE organization_id = ?
      ORDER BY created_at DESC
      LIMIT 100
    `).all(req.organizationId);
    res.json({ success: true, campaigns });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/campaigns', requireOrganizationMembership, requirePermission(PERMISSIONS.CAMPAIGNS_CREATE), (req, res) => {
  const { name, description, type } = req.body;
  if (!name || !type) return res.status(400).json({ error: 'Name and type are required.' });
  // Type must be an educational simulation type. Let's just trust for now but ensure it's not real harvesting.
  
  const id = uuidv4();
  try {
    db.prepare(`
      INSERT INTO security_campaigns (id, organization_id, name, description, type, created_by)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(id, req.organizationId, name, description, type, req.session.userId);

    logOrganizationEvent(req.organizationId, req.session.userId, 'CAMPAIGN_CREATED', req, { campaignId: id, type });
    res.json({ success: true, campaignId: id });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/campaigns/:id/launch', requireOrganizationMembership, requirePermission(PERMISSIONS.CAMPAIGNS_LAUNCH), (req, res) => {
  const { id } = req.params;
  try {
    const campaign = db.prepare('SELECT status FROM security_campaigns WHERE id = ? AND organization_id = ?').get(id, req.organizationId);
    if (!campaign) return res.status(404).json({ error: 'Campaign not found.' });
    if (campaign.status !== 'DRAFT' && campaign.status !== 'READY') return res.status(400).json({ error: 'Campaign cannot be launched in its current state.' });

    db.transaction(() => {
      db.prepare("UPDATE security_campaigns SET status = 'RUNNING', started_at = CURRENT_TIMESTAMP WHERE id = ?").run(id);
      db.prepare('INSERT INTO campaign_events (id, campaign_id, event_type) VALUES (?, ?, ?)')
        .run(uuidv4(), id, 'CAMPAIGN_LAUNCHED');
    })();

    logOrganizationEvent(req.organizationId, req.session.userId, 'CAMPAIGN_LAUNCHED', req, { campaignId: id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/campaigns/:id/cancel', requireOrganizationMembership, requirePermission(PERMISSIONS.CAMPAIGNS_CANCEL), (req, res) => {
  const { id } = req.params;
  try {
    const campaign = db.prepare('SELECT status FROM security_campaigns WHERE id = ? AND organization_id = ?').get(id, req.organizationId);
    if (!campaign) return res.status(404).json({ error: 'Campaign not found.' });

    db.transaction(() => {
      db.prepare("UPDATE security_campaigns SET status = 'CANCELLED', ended_at = CURRENT_TIMESTAMP WHERE id = ?").run(id);
      db.prepare('INSERT INTO campaign_events (id, campaign_id, event_type) VALUES (?, ?, ?)')
        .run(uuidv4(), id, 'CAMPAIGN_CANCELLED');
    })();

    logOrganizationEvent(req.organizationId, req.session.userId, 'CAMPAIGN_CANCELLED', req, { campaignId: id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/campaigns/:id/pause', requireOrganizationMembership, requirePermission(PERMISSIONS.CAMPAIGNS_PAUSE), (req, res) => {
  const { id } = req.params;
  try {
    const campaign = db.prepare('SELECT status FROM security_campaigns WHERE id = ? AND organization_id = ?').get(id, req.organizationId);
    if (!campaign) return res.status(404).json({ error: 'Campaign not found.' });
    if (campaign.status !== 'RUNNING') return res.status(400).json({ error: 'Campaign is not running.' });

    db.transaction(() => {
      db.prepare("UPDATE security_campaigns SET status = 'PAUSED' WHERE id = ?").run(id);
      db.prepare('INSERT INTO campaign_events (id, campaign_id, event_type) VALUES (?, ?, ?)')
        .run(uuidv4(), id, 'CAMPAIGN_PAUSED');
    })();

    logOrganizationEvent(req.organizationId, req.session.userId, 'CAMPAIGN_PAUSED', req, { campaignId: id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

module.exports = router;
