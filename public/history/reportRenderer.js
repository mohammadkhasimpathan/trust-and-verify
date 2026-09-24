/**
 * reportRenderer.js
 * Generates JSON, CSV and Print/PDF representations of history records.
 */

const REPORT_SCHEMA_VERSION = "1.0";

function generateJSONReport(scan) {
  const report = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    application: "Trust & Verify",
    generatedAt: new Date().toISOString(),
    scan: {
      id: scan.id,
      module: scan.module,
      target: scan.target.display,
      createdAt: scan.createdAt,
      updatedAt: scan.updatedAt
    },
    result: scan.result,
    threatIntelligence: scan.threatIntelligence || [],
    limitations: "This report reflects the analysis available at the time of the scan. A low-risk result does not guarantee that the target is safe. External threat intelligence depends on provider availability, configuration, quotas and provider data."
  };
  return JSON.stringify(report, null, 2);
}

function sanitizeCsvValue(val) {
  if (val === null || val === undefined) return '';
  let str = String(val);
  // CSV Injection protection
  if (str.startsWith('=') || str.startsWith('+') || str.startsWith('-') || str.startsWith('@')) {
    str = "'" + str;
  }
  // Escape quotes
  if (str.includes('"') || str.includes(',') || str.includes('\n')) {
    str = '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

function generateCSVReport(scan) {
  const headers = [
    'Scan ID', 'Timestamp', 'Module', 'Target', 
    'Score', 'Severity', 'Verdict', 'Finding Count', 'Threat Intel Status'
  ];
  
  const tiStatus = (scan.threatIntelligence && scan.threatIntelligence.length > 0) ? 'CHECKED' : 'NOT CHECKED';
  
  const row = [
    scan.id,
    scan.createdAt,
    scan.module,
    scan.target.display,
    scan.result?.score || 0,
    scan.result?.severity || 'UNKNOWN',
    scan.result?.verdict || 'UNKNOWN',
    scan.result?.indicators?.length || 0,
    tiStatus
  ];
  
  return headers.join(',') + '\n' + row.map(sanitizeCsvValue).join(',');
}

function printReport(scan) {
  // Rather than generating a complex PDF directly via JS libraries, 
  // we open a clean printable window containing the report and trigger print()
  const w = window.open('', '_blank');
  
  const escapeHtml = (unsafe) => {
    return (unsafe||'').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  };
  
  // HTML Template for Print/PDF rendering
  w.document.write(`
    <html>
      <head>
        <title>Security Analysis Report - ${escapeHtml(scan.id)}</title>
        <style>
          body { font-family: sans-serif; color: #333; margin: 40px; }
          h1 { border-bottom: 2px solid #333; padding-bottom: 10px; }
          h2 { margin-top: 30px; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
          .meta { font-size: 12px; color: #666; margin-bottom: 30px; }
          table { width: 100%; border-collapse: collapse; margin-top: 15px; table-layout: fixed; }
          th, td { border: 1px solid #ddd; padding: 8px; text-align: left; word-wrap: break-word; }
          th { background-color: #f4f4f4; width: 25%; }
          .risk-high { color: #d32f2f; font-weight: bold; }
          .limitations { margin-top: 50px; font-size: 11px; color: #777; border-top: 1px dashed #ccc; padding-top: 10px; }
          @media print {
            body { margin: 0; }
            h2 { page-break-after: avoid; }
            table { page-break-inside: auto; }
            tr { page-break-inside: avoid; page-break-after: auto; }
          }
        </style>
      </head>
      <body>
        <h1>Trust & Verify - Security Analysis Report</h1>
        <div class="meta">
          <strong>Scan ID:</strong> ${escapeHtml(scan.id)}<br>
          <strong>Generated:</strong> ${new Date().toISOString()}<br>
          <strong>Module:</strong> ${escapeHtml(scan.module)}<br>
          <strong>Target:</strong> ${escapeHtml(scan.target.display)}
        </div>
        
        <h2>Executive Summary</h2>
        <table>
          <tr><th>Risk Score</th><td>${scan.result?.score || 0}/100</td></tr>
          <tr><th>Severity</th><td class="${scan.result?.score > 50 ? 'risk-high' : ''}">${escapeHtml(scan.result?.severity || 'UNKNOWN')}</td></tr>
          <tr><th>Verdict</th><td>${escapeHtml(scan.result?.verdict || 'UNKNOWN')}</td></tr>
        </table>
        
        <h2>Findings</h2>
        <table>
          <tr><th>Severity</th><th>Title</th><th>Evidence</th><th>Source</th></tr>
          ${(scan.result?.indicators || []).map(ind => `
            <tr>
              <td>${escapeHtml(ind.severity)}</td>
              <td>${escapeHtml(ind.title)}</td>
              <td>${escapeHtml(ind.evidence || ind.description || '')}</td>
              <td>${escapeHtml(ind.category || 'LOCAL')}</td>
            </tr>
          `).join('')}
        </table>
        
        ${(scan.threatIntelligence && scan.threatIntelligence.length > 0) ? `
          <h2>Threat Intelligence</h2>
          <table>
            <tr><th>Provider</th><th>Status</th></tr>
            ${scan.threatIntelligence.map(ti => `
              <tr>
                <td>${escapeHtml(ti.provider)}</td>
                <td>${escapeHtml(ti.status)}</td>
              </tr>
            `).join('')}
          </table>
        ` : ''}
        
        <div class="limitations">
          <strong>Limitations:</strong><br>
          This report reflects the analysis available at the time of the scan. A low-risk result does not guarantee that the target is safe. External threat intelligence depends on provider availability, configuration, quotas and provider data.
        </div>
      </body>
    </html>
  `);
  w.document.close();
  w.focus();
  setTimeout(() => {
    w.print();
  }, 250);
}

if (typeof window !== 'undefined') window.reportRenderer = { generateJSONReport, generateCSVReport, sanitizeCsvValue, printReport, REPORT_SCHEMA_VERSION };
if (typeof module !== 'undefined') module.exports = { generateJSONReport, generateCSVReport, sanitizeCsvValue, printReport, REPORT_SCHEMA_VERSION };
