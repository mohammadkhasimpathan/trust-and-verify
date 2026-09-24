// progressManager.js
/**
 * ProgressManager handles interaction with the training IndexedDB stores.
 */

class ProgressManager {
  constructor() {
    this.store = typeof window !== 'undefined' && window.historyStore ? window.historyStore : null;
  }

  async _getDbStore(storeName, mode) {
    if (!this.store || !this.store.db) {
      if (this.store && this.store.initPromise) {
        await this.store.initPromise;
      } else {
        throw new Error('Database not initialized');
      }
    }
    const tx = this.store.db.transaction(storeName, mode);
    return tx.objectStore(storeName);
  }

  // --- Training Events ---
  async logEvent(eventType, activityId, points, details = {}) {
    const event = {
      eventId: 'evt_' + Math.random().toString(36).substr(2, 9),
      eventType,
      activityId,
      points,
      details,
      timestamp: new Date().toISOString()
    };
    
    const store = await this._getDbStore('trainingEvents', 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.put(event);
      req.onsuccess = () => resolve(event);
      req.onerror = () => reject(req.error);
    });
  }

  async getEvents() {
    const store = await this._getDbStore('trainingEvents', 'readonly');
    return new Promise((resolve, reject) => {
      const req = store.getAll();
      req.onsuccess = () => {
        const events = req.result;
        events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        resolve(events);
      };
      req.onerror = () => reject(req.error);
    });
  }

  // --- Training Progress ---
  async getProgress(id) {
    const store = await this._getDbStore('trainingProgress', 'readonly');
    return new Promise((resolve, reject) => {
      const req = store.get(id);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async saveProgress(progressObj) {
    const store = await this._getDbStore('trainingProgress', 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.put(progressObj);
      req.onsuccess = () => resolve(progressObj);
      req.onerror = () => reject(req.error);
    });
  }
  
  async getAllProgress() {
    const store = await this._getDbStore('trainingProgress', 'readonly');
    return new Promise((resolve, reject) => {
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  // --- Quiz Attempts ---
  async getQuizAttempt(id) {
    const store = await this._getDbStore('quizAttempts', 'readonly');
    return new Promise((resolve, reject) => {
      const req = store.get(id);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async saveQuizAttempt(attempt) {
    const store = await this._getDbStore('quizAttempts', 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.put(attempt);
      req.onsuccess = () => resolve(attempt);
      req.onerror = () => reject(req.error);
    });
  }

  // --- Challenge Attempts ---
  async getChallengeAttempt(id) {
    const store = await this._getDbStore('challengeAttempts', 'readonly');
    return new Promise((resolve, reject) => {
      const req = store.get(id);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async saveChallengeAttempt(attempt) {
    const store = await this._getDbStore('challengeAttempts', 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.put(attempt);
      req.onsuccess = () => resolve(attempt);
      req.onerror = () => reject(req.error);
    });
  }

  // --- Badges ---
  async getBadges() {
    const store = await this._getDbStore('badges', 'readonly');
    return new Promise((resolve, reject) => {
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async unlockBadge(badge) {
    const store = await this._getDbStore('badges', 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.put(badge);
      req.onsuccess = () => resolve(badge);
      req.onerror = () => reject(req.error);
    });
  }

  // --- Certificates ---
  async getCertificates() {
    const store = await this._getDbStore('certificates', 'readonly');
    return new Promise((resolve, reject) => {
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async saveCertificate(cert) {
    const store = await this._getDbStore('certificates', 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.put(cert);
      req.onsuccess = () => resolve(cert);
      req.onerror = () => reject(req.error);
    });
  }

  async resetTrainingProgress() {
    const stores = ['trainingProgress', 'quizAttempts', 'challengeAttempts', 'badges', 'certificates', 'trainingEvents'];
    for (const name of stores) {
      const store = await this._getDbStore(name, 'readwrite');
      await new Promise((resolve, reject) => {
        const req = store.clear();
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
      });
    }
  }
}

if (typeof window !== 'undefined') {
  window.progressManager = new ProgressManager();
}
