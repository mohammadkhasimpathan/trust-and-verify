/**
 * historyStore.js
 * IndexedDB wrapper for Trust & Verify scan history.
 */

const DB_NAME = 'trustVerify';
const DB_VERSION = 1;
const STORE_NAME = 'scans';
const MAX_RECORDS = 500;

class HistoryStore {
  constructor() {
    this.db = null;
    this.initPromise = this._init();
  }

  _init() {
    return new Promise((resolve, reject) => {
      if (typeof window === 'undefined' || !window.indexedDB) {
        console.warn('IndexedDB not supported in this environment.');
        return reject(new Error('IndexedDB not supported'));
      }
      const request = window.indexedDB.open(DB_NAME, DB_VERSION);
      
      request.onerror = (e) => reject(e.target.error);
      
      request.onsuccess = (e) => {
        this.db = e.target.result;
        resolve();
      };
      
      request.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          const store = db.createObjectStore(STORE_NAME, { keyPath: 'id' });
          store.createIndex('timestamp', 'createdAt', { unique: false });
          store.createIndex('module', 'module', { unique: false });
          store.createIndex('severity', 'result.severity', { unique: false });
        }
      };
    });
  }

  async _getStore(mode) {
    await this.initPromise;
    const tx = this.db.transaction(STORE_NAME, mode);
    return tx.objectStore(STORE_NAME);
  }

  async saveScan(scan) {
    const store = await this._getStore('readwrite');
    return new Promise((resolve, reject) => {
      // Enforce max limit before saving
      const countReq = store.count();
      countReq.onsuccess = () => {
        if (countReq.result >= MAX_RECORDS) {
           return reject(new Error(`History storage limit reached (${MAX_RECORDS}). Please delete older scans before saving new ones.`));
        }
        const request = store.put(scan);
        request.onsuccess = () => resolve(scan.id);
        request.onerror = () => reject(request.error);
      };
    });
  }

  async updateScan(id, patch) {
    const store = await this._getStore('readwrite');
    return new Promise((resolve, reject) => {
      const getReq = store.get(id);
      getReq.onsuccess = () => {
        if (!getReq.result) return reject(new Error('Scan not found'));
        const updated = { ...getReq.result, ...patch, updatedAt: new Date().toISOString() };
        const putReq = store.put(updated);
        putReq.onsuccess = () => resolve(updated);
        putReq.onerror = () => reject(putReq.error);
      };
      getReq.onerror = () => reject(getReq.error);
    });
  }

  async getScan(id) {
    const store = await this._getStore('readonly');
    return new Promise((resolve, reject) => {
      const req = store.get(id);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async deleteScan(id) {
    const store = await this._getStore('readwrite');
    return new Promise((resolve, reject) => {
      const req = store.delete(id);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async clearAllScans() {
    const store = await this._getStore('readwrite');
    return new Promise((resolve, reject) => {
      const req = store.clear();
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async listScans(options = {}) {
    const store = await this._getStore('readonly');
    return new Promise((resolve, reject) => {
      const index = store.index('timestamp');
      const req = index.openCursor(null, 'prev'); // Newest first
      const results = [];
      let skipped = 0;
      const skip = options.skip || 0;
      const limit = options.limit || 25;
      
      req.onsuccess = (e) => {
        const cursor = e.target.result;
        if (cursor && results.length < limit) {
          let match = true;
          const val = cursor.value;
          
          if (options.module && options.module !== 'All' && val.module !== options.module) match = false;
          if (options.severity && options.severity !== 'All' && val.result?.severity !== options.severity) match = false;
          if (options.verdict && options.verdict !== 'All' && val.result?.verdict !== options.verdict) match = false;
          if (options.search) {
             const searchLower = options.search.toLowerCase();
             if (!val.target?.display?.toLowerCase().includes(searchLower) && 
                 !val.module.toLowerCase().includes(searchLower)) {
                 match = false;
             }
          }
          
          if (match) {
            if (skipped < skip) {
              skipped++;
            } else {
              results.push(val);
            }
          }
          cursor.continue();
        } else {
          resolve(results);
        }
      };
      req.onerror = () => reject(req.error);
    });
  }
  
  async countScans() {
    const store = await this._getStore('readonly');
    return new Promise((resolve, reject) => {
      const req = store.count();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
}

if (typeof window !== 'undefined') window.historyStore = new HistoryStore();
if (typeof module !== 'undefined') module.exports = HistoryStore;
