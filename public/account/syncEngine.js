// syncEngine.js

class SyncEngine {
  constructor() {
    this.deviceId = this._getOrCreateDeviceId();
    this.syncing = false;
  }

  _getOrCreateDeviceId() {
    let id = localStorage.getItem('tv_device_id');
    if (!id) {
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

  async login(email, password, totp) {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, totp })
    });
    const data = await res.json();
    if (!res.ok) {
      if (data.error === 'MFA_REQUIRED') {
        throw new Error('MFA_REQUIRED');
      }
      throw new Error(data.error || 'Login failed.');
    }
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

  async forgotPassword(email) {
    const res = await fetch('/api/auth/forgot-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to send reset email.');
    return data;
  }

  async resetPassword(token, newPassword) {
    const res = await fetch('/api/auth/reset-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, newPassword })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to reset password.');
    return data;
  }
  
  async changePassword(currentPassword, newPassword) {
    const res = await fetch('/api/auth/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword, newPassword })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to change password.');
    return data;
  }

  async verifyEmailToken(token) {
    const res = await fetch('/api/auth/verify-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Verification failed.');
    return data;
  }

  async mfaSetup() {
    const res = await fetch('/api/auth/mfa/setup', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to setup MFA.');
    return data; // { secret, otpauth }
  }

  async mfaVerify(totp) {
    const res = await fetch('/api/auth/mfa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ totp })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to verify MFA.');
    return data; // { backupCodes }
  }

  async mfaDisable(password, totp) {
    const res = await fetch('/api/auth/mfa/disable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password, totp })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to disable MFA.');
    return data;
  }

  async getSessions() {
    const res = await fetch('/api/auth/sessions');
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to load sessions.');
    return data.sessions;
  }

  async revokeSession(id) {
    const res = await fetch(`/api/auth/sessions/${id}/revoke`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to revoke session.');
  }

  async revokeOtherSessions() {
    const res = await fetch('/api/auth/sessions/revoke-others', { method: 'POST' });
    if (!res.ok) throw new Error('Failed to revoke other sessions.');
  }

  async getSecurityEvents() {
    const res = await fetch('/api/auth/security-events');
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to load security events.');
    return data.events;
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
      
      await this.pushLocalChanges();
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
    if (!window.historyStore || !window.progressManager) return;
    const queue = [];
    
    // Quick collect
    const scans = await window.historyStore.getAllScans();
    scans.forEach(s => queue.push({ id: 'push_s_'+s.id, entityType: 'scans', entityId: s.id, operation: 'CREATE', payload: s }));
    const tp = await window.progressManager.getAllProgress();
    tp.forEach(p => queue.push({ id: 'push_tp_'+p.id, entityType: 'trainingProgress', entityId: p.id, operation: 'CREATE', payload: p }));
    
    for (let storeName of ['quizAttempts', 'challengeAttempts', 'badges', 'certificates']) {
      const store = await window.progressManager._getDbStore(storeName, 'readonly');
      const items = await new Promise(r => { const req = store.getAll(); req.onsuccess = () => r(req.result); });
      items.forEach(i => queue.push({ id: `push_${storeName}_${i.id}`, entityType: storeName, entityId: i.id, operation: 'CREATE', payload: i }));
    }
    
    const events = await window.progressManager.getEvents();
    events.forEach(e => queue.push({ id: 'push_evt_'+e.eventId, entityType: 'trainingEvents', entityId: e.eventId, operation: 'CREATE', payload: e }));

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
    
    if (window.historyStore && window.progressManager) {
      if (data.scans) {
        for (const s of data.scans) {
          await window.historyStore.saveScan({
            id: s.id, module: s.module, score: s.score, severity: s.severity, verdict: s.verdict,
            summary: s.summary, indicators: JSON.parse(s.indicators), recommendations: JSON.parse(s.recommendations),
            metadata: JSON.parse(s.metadata), fingerprint: s.fingerprint, engineVersion: s.engine_version,
            timestamp: s.created_at
          });
        }
      }
      
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
    }
  }
}

if (typeof window !== 'undefined') window.syncEngine = new SyncEngine();
