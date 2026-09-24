// syncEngine.js

class SyncEngine {
  constructor() {
    this.deviceId = this._getOrCreateDeviceId();
    this.syncing = false;
  }

  _getOrCreateDeviceId() {
    let id = localStorage.getItem('tv_device_id');
    if (!id) {
      // Basic random UUID v4 logic for browser without requiring an external lib
      id = crypto.randomUUID ? crypto.randomUUID() : 'dev_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
      localStorage.setItem('tv_device_id', id);
    }
    return id;
  }

  async checkAuthStatus() {
    try {
      const res = await fetch('/api/auth/session');
      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      console.warn('[Sync] Offline or server unavailable.');
    }
    return { authenticated: false };
  }

  async login(email, password) {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Login failed.');
    return data;
  }

  async register(email, password, displayName) {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, displayName })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Registration failed.');
    return data;
  }

  async logout() {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch (e) {
      console.warn('Logout request failed', e);
    }
  }

  async deleteAccount() {
    const res = await fetch('/api/auth/account', { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete account.');
  }

  async syncNow() {
    if (this.syncing) return;
    this.syncing = true;
    try {
      const auth = await this.checkAuthStatus();
      if (!auth.authenticated) {
        this.syncing = false;
        return;
      }
      
      if (window.addLogLine) window.addLogLine('[SYNC] Starting synchronization...', 'system');
      
      // Push local changes
      await this.pushLocalChanges();
      
      // Pull server changes
      await this.pullServerChanges();
      
      if (window.addLogLine) window.addLogLine('[SYNC] Synchronization complete.', 'success');
    } catch (err) {
      console.error(err);
      if (window.addLogLine) window.addLogLine('[SYNC] Synchronization failed: ' + err.message, 'error');
    } finally {
      this.syncing = false;
    }
  }

  async pushLocalChanges() {
    // Collect data to push. In a real app we'd have a syncQueue.
    // For Phase 7, we'll push all local data. The server ignores duplicates.
    
    if (!window.historyStore || !window.progressManager) return;
    
    const queue = [];
    
    // Scans
    const scans = await window.historyStore.getAllScans();
    scans.forEach(s => queue.push({ id: 'push_s_'+s.id, entityType: 'scans', entityId: s.id, operation: 'CREATE', payload: s }));
    
    // Training Progress
    const tp = await window.progressManager.getAllProgress();
    tp.forEach(p => queue.push({ id: 'push_tp_'+p.id, entityType: 'trainingProgress', entityId: p.id, operation: 'CREATE', payload: p }));
    
    // Quiz Attempts
    const qstore = await window.progressManager._getDbStore('quizAttempts', 'readonly');
    const qa = await new Promise(r => { const req = qstore.getAll(); req.onsuccess = () => r(req.result); });
    qa.forEach(a => queue.push({ id: 'push_qa_'+a.id, entityType: 'quizAttempts', entityId: a.id, operation: 'CREATE', payload: a }));
    
    // Challenge Attempts
    const cstore = await window.progressManager._getDbStore('challengeAttempts', 'readonly');
    const ca = await new Promise(r => { const req = cstore.getAll(); req.onsuccess = () => r(req.result); });
    ca.forEach(a => queue.push({ id: 'push_ca_'+a.id, entityType: 'challengeAttempts', entityId: a.id, operation: 'CREATE', payload: a }));
    
    // Badges
    const bstore = await window.progressManager._getDbStore('badges', 'readonly');
    const ba = await new Promise(r => { const req = bstore.getAll(); req.onsuccess = () => r(req.result); });
    ba.forEach(b => queue.push({ id: 'push_b_'+b.id, entityType: 'badges', entityId: b.id, operation: 'CREATE', payload: b }));
    
    // Certificates
    const certstore = await window.progressManager._getDbStore('certificates', 'readonly');
    const cert = await new Promise(r => { const req = certstore.getAll(); req.onsuccess = () => r(req.result); });
    cert.forEach(c => queue.push({ id: 'push_cert_'+c.id, entityType: 'certificates', entityId: c.id, operation: 'CREATE', payload: c }));
    
    // Training Events
    const events = await window.progressManager.getEvents();
    events.forEach(e => queue.push({ id: 'push_evt_'+e.eventId, entityType: 'trainingEvents', entityId: e.eventId, operation: 'CREATE', payload: e }));

    // Send chunks of 500
    for (let i = 0; i < queue.length; i += 500) {
      const chunk = queue.slice(i, i + 500);
      const res = await fetch('/api/sync/push', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queue: chunk, deviceId: this.deviceId })
      });
      if (!res.ok) throw new Error('Push request failed.');
    }
  }

  async pullServerChanges() {
    const res = await fetch('/api/sync/pull', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceId: this.deviceId })
    });
    
    if (!res.ok) throw new Error('Pull request failed.');
    const { data } = await res.json();
    
    // Merge into local DB
    if (window.historyStore && window.progressManager) {
      if (data.scans) {
        for (const s of data.scans) {
          const payload = {
            id: s.id, module: s.module, score: s.score, severity: s.severity, verdict: s.verdict,
            summary: s.summary, indicators: JSON.parse(s.indicators), recommendations: JSON.parse(s.recommendations),
            metadata: JSON.parse(s.metadata), fingerprint: s.fingerprint, engineVersion: s.engine_version,
            timestamp: s.created_at
          };
          await window.historyStore.saveScan(payload);
        }
      }
      
      // Update other stores similarly
      if (data.badges) {
        const bstore = await window.progressManager._getDbStore('badges', 'readwrite');
        for (const b of data.badges) {
          await new Promise(r => { const req = bstore.put({ id: b.id, unlockedAt: b.unlocked_at }); req.onsuccess = r; });
        }
      }

      if (data.trainingEvents) {
        const estore = await window.progressManager._getDbStore('trainingEvents', 'readwrite');
        for (const e of data.trainingEvents) {
          await new Promise(r => { 
            const req = estore.put({ eventId: e.event_id, eventType: e.event_type, activityId: e.activity_id, points: e.points, details: JSON.parse(e.details), timestamp: e.timestamp }); 
            req.onsuccess = r; 
          });
        }
      }
      
      // Note: A full implementation would apply conflict resolution. For this phase, server data is pulled and blindly overwrites local.
    }
  }
}

if (typeof window !== 'undefined') window.syncEngine = new SyncEngine();
