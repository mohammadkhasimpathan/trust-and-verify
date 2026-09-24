/**
 * historyUi.js
 * Handles UI interactions for the Scan History module.
 */

class HistoryUI {
  constructor() {
    this.currentPage = 1;
    this.pageSize = 25;
    this.searchTimeout = null;
    this.currentScanDetail = null;
  }

  escapeHtml(unsafe) {
    return (unsafe||'').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }

  debouncedLoad() {
    if (this.searchTimeout) clearTimeout(this.searchTimeout);
    this.searchTimeout = setTimeout(() => {
      this.currentPage = 1;
      this.loadHistory();
    }, 300);
  }

  async loadHistory() {
    const listEl = document.getElementById('history-list');
    if (!listEl) return;
    
    listEl.innerHTML = '<div class="empty-findings-state">Loading history...</div>';
    
    try {
      const moduleFilter = document.getElementById('history-filter-module').value;
      const severityFilter = document.getElementById('history-filter-severity').value;
      const search = document.getElementById('history-search').value;
      
      const options = {
        skip: (this.currentPage - 1) * this.pageSize,
        limit: this.pageSize,
        module: moduleFilter,
        severity: severityFilter,
        search: search
      };
      
      const results = await window.historyStore.listScans(options);
      this.renderList(results);
      
      // We don't know total count of filtered, just do simple prev/next logic
      document.getElementById('history-prev-btn').disabled = this.currentPage === 1;
      document.getElementById('history-next-btn').disabled = results.length < this.pageSize;
      document.getElementById('history-page-info').textContent = `Page ${this.currentPage}`;
      
    } catch (e) {
      listEl.innerHTML = `<div class="empty-findings-state" style="color: #ff4444;">Error loading history: ${this.escapeHtml(e.message)}</div>`;
    }
  }

  renderList(results) {
    const listEl = document.getElementById('history-list');
    if (results.length === 0) {
      listEl.innerHTML = '<div class="empty-findings-state">No scan history found matching criteria.</div>';
      return;
    }
    
    let html = '';
    for (const scan of results) {
      const dateStr = new Date(scan.createdAt).toLocaleString();
      const scoreColor = scan.result?.score > 50 ? '#d32f2f' : '#00f0ff';
      const tiText = scan.threatIntelligence && scan.threatIntelligence.length > 0 ? 'Ext. Intel' : 'Local Only';
      
      html += `
        <div style="background: rgba(0,240,255,0.05); border: 1px solid rgba(0,240,255,0.2); padding: 10px; cursor: pointer;" onclick="historyUi.viewDetail('${scan.id}')">
          <div style="display: flex; justify-content: space-between; align-items: flex-start;">
            <div>
              <strong style="color: #00f0ff;">[${this.escapeHtml(scan.module)}]</strong> 
              <span style="color: #fff;">${this.escapeHtml(scan.target.display)}</span>
              <div style="font-size: 11px; color: #aaa; margin-top: 5px;">${dateStr} | ${tiText}</div>
            </div>
            <div style="text-align: right;">
              <strong style="color: ${scoreColor}; font-size: 14px;">${scan.result?.score || 0}/100</strong>
              <div style="font-size: 11px; color: ${scoreColor};">${this.escapeHtml(scan.result?.severity || 'UNKNOWN')}</div>
            </div>
          </div>
        </div>
      `;
    }
    listEl.innerHTML = html;
  }

  prevPage() {
    if (this.currentPage > 1) {
      this.currentPage--;
      this.loadHistory();
    }
  }

  nextPage() {
    this.currentPage++;
    this.loadHistory();
  }

  async clearHistory() {
    if (confirm('This will permanently remove all locally stored Trust & Verify scan history from this browser. Continue?')) {
      await window.historyStore.clearAllScans();
      this.currentPage = 1;
      this.loadHistory();
    }
  }
  
  async deleteRecord(id) {
    if (confirm('Delete this history record permanently?')) {
      await window.historyStore.deleteScan(id);
      this.loadHistory();
      
      // If we are showing the diagnostic panel for this scan, clear it
      if (this.currentScanDetail && this.currentScanDetail.id === id) {
        document.getElementById('findings-list').innerHTML = '<div class="empty-findings-state">Select a scan from history to view details.</div>';
        this.currentScanDetail = null;
      }
    }
  }

  async viewDetail(id) {
    try {
      const scan = await window.historyStore.getScan(id);
      if (!scan) return alert('Scan not found.');
      this.currentScanDetail = scan;
      this.renderDiagnosticPanel(scan);
      
      // Also scroll to top if mobile
      if (window.innerWidth < 900) {
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
    } catch (e) {
      alert('Error loading scan details.');
    }
  }
  
  renderDiagnosticPanel(scan) {
    // We update the right column "Results Panel" manually here instead of relying on the main module scanner
    if (typeof updateThreatGauge === 'function') {
      updateThreatGauge(scan.result?.score || 0, scan.result?.threatLevel || (scan.result?.score > 50 ? 'High' : 'Low'));
    }
    
    // Clear and build finding HTML directly to include report export buttons
    const findingsList = document.getElementById('findings-list');
    
    let html = `
      <div style="margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #333;">
        <h4 style="margin: 0 0 10px 0; color: #fff;">HISTORY RECORD DETAILS</h4>
        <div style="font-size: 11px; color: #aaa; margin-bottom: 15px;">
          <strong>Target:</strong> ${this.escapeHtml(scan.target.display)}<br>
          <strong>Date:</strong> ${new Date(scan.createdAt).toLocaleString()}<br>
          <strong>Module:</strong> ${this.escapeHtml(scan.module)}<br>
        </div>
        
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <button class="action-btn secondary-action" style="padding: 4px 10px; font-size: 11px;" onclick="historyUi.exportJSON()">JSON</button>
          <button class="action-btn secondary-action" style="padding: 4px 10px; font-size: 11px;" onclick="historyUi.exportCSV()">CSV</button>
          <button class="action-btn secondary-action" style="padding: 4px 10px; font-size: 11px;" onclick="historyUi.printPDF()">Print / PDF</button>
          <button class="action-btn danger-action" style="padding: 4px 10px; font-size: 11px; background: rgba(211,47,47,0.2); color: #ff4444; border: 1px solid #d32f2f;" onclick="historyUi.deleteRecord('${scan.id}')">Delete</button>
        </div>
      </div>
    `;
    
    const allIndicators = scan.result?.indicators || [];
    if (allIndicators.length === 0) {
      html += `<div class="empty-findings-state">No suspicious indicators recorded in this scan.</div>`;
    } else {
      for (const f of allIndicators) {
        html += `
          <div class="finding-item" style="border-left-color: ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? '#ff3333' : (f.severity === 'MEDIUM' ? '#ffaa00' : '#00ffcc')}">
            <div class="finding-header">
              <span class="finding-severity ${f.severity.toLowerCase()}">${this.escapeHtml(f.severity)}</span>
              <span class="finding-title">${this.escapeHtml(f.title)}</span>
            </div>
            <div class="finding-body">
              <div class="finding-evidence"><strong>Evidence:</strong> ${this.escapeHtml(f.evidence || f.description || '')}</div>
              <div class="finding-source"><strong>Source:</strong> ${this.escapeHtml(f.category || 'LOCAL')}</div>
            </div>
          </div>
        `;
      }
    }
    
    findingsList.innerHTML = html;
    
    // Also render threat intel if available
    const tiPanel = document.getElementById('threat-intel-results');
    const tiGrid = document.getElementById('ti-providers-grid');
    if (scan.threatIntelligence && scan.threatIntelligence.length > 0 && tiPanel && tiGrid) {
      tiPanel.style.display = 'block';
      let tiHtml = '';
      scan.threatIntelligence.forEach(provider => {
         const color = provider.status === 'SAFE' || provider.status === 'CLEAN' ? 'success' : (provider.status === 'FOUND' || provider.status === 'MALICIOUS' ? 'danger' : 'warn');
         tiHtml += `
           <div class="header-card">
             <div class="header-key">${this.escapeHtml(provider.provider)}</div>
             <div class="header-value"><span style="color: var(--color-${color})">${this.escapeHtml(provider.status)}</span></div>
             <div class="header-raw" style="margin-top: 5px; font-size: 10px;">Queried: ${new Date(provider.queriedAt || scan.createdAt).toLocaleString()}</div>
           </div>
         `;
      });
      tiGrid.innerHTML = tiHtml;
    } else if (tiPanel) {
      tiPanel.style.display = 'none';
    }
  }
  
  _downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  exportJSON() {
    if (!this.currentScanDetail) return;
    const jsonStr = window.reportRenderer.generateJSONReport(this.currentScanDetail);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    this._downloadBlob(blob, `trust-verify-report-${this.currentScanDetail.id.slice(0,8)}.json`);
  }
  
  exportCSV() {
    if (!this.currentScanDetail) return;
    const csvStr = window.reportRenderer.generateCSVReport(this.currentScanDetail);
    const blob = new Blob([csvStr], { type: 'text/csv' });
    this._downloadBlob(blob, `trust-verify-report-${this.currentScanDetail.id.slice(0,8)}.csv`);
  }
  
  printPDF() {
    if (!this.currentScanDetail) return;
    window.reportRenderer.printReport(this.currentScanDetail);
  }
}

if (typeof window !== 'undefined') window.historyUi = new HistoryUI();
