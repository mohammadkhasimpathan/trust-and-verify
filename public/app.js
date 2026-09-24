/**
 * app.js
 * Unified Frontend Controller for the Trust & Verify Unified Cyber Defense Suite.
 * Coordinates module tabs, executes scans, simulates AI call intercepts, and generates Audio context alerts.
 */

// Global App States
let activeModule = 'email';
let activeEmailTab = 'headers';
let selectedFile = null;
let selectedEml = null;
let simulatedFileData = null;
let currentScenario = 'irs';

// Call Interceptor Simulation State
let callTimerInterval = null;
let callStepTimeout = null;
let callDuration = 0;
let callStepIdx = 0;
let callThreatScore = 0;
let isCallActive = false;

// Audio Alarm System States
let audioCtx = null;
let isAudioAlarmEnabled = true;
let isSirenPlaying = false;
let sirenOsc1 = null;
let sirenOsc2 = null;
let sirenGain = null;
let sirenInterval = null;

// PWA Install Prompt State
let deferredInstallPrompt = null;

// 1. PWA Service Worker Registration
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js')
      .then(reg => console.log('[PWA] Service Worker registered with scope:', reg.scope))
      .catch(err => console.error('[PWA] Service Worker registration failed:', err));
  });
}

// Handle PWA installation prompts
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredInstallPrompt = e;
  const installBtn = document.getElementById('btn-install-pwa');
  if (installBtn) {
    installBtn.style.display = 'block'; // Show install button in sidebar
  }
});

function installPWA() {
  if (!deferredInstallPrompt) return;
  deferredInstallPrompt.prompt();
  deferredInstallPrompt.userChoice.then((choiceResult) => {
    if (choiceResult.outcome === 'accepted') {
      console.log('[PWA] User accepted installation.');
    }
    deferredInstallPrompt = null;
    document.getElementById('btn-install-pwa').style.display = 'none';
  });
}

// 2. Web Audio API Alarm Synthesizer
function initAudioContext() {
  if (!audioCtx) {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    document.getElementById('audio-init-prompt').style.display = 'none';
    addLogLine('[SYSTEM] Web Audio Context initialized successfully.', 'success');
    
    // Play sci-fi startup arpeggio chime
    playStartupChime();
  }
}

function playStartupChime() {
  if (!audioCtx) return;
  try {
    if (audioCtx.state === 'suspended') {
      audioCtx.resume();
    }
    const now = audioCtx.currentTime;
    // Cyber chord frequencies (C major 9 arpeggio: C3, G3, D4, E4, G4, B4, D5)
    const notes = [130.81, 196.00, 293.66, 329.63, 392.00, 493.88, 587.33];
    
    notes.forEach((freq, idx) => {
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      
      osc.type = idx % 2 === 0 ? 'triangle' : 'sine';
      osc.frequency.setValueAtTime(freq, now + idx * 0.07);
      
      // Rising arpeggio volume envelope
      gain.gain.setValueAtTime(0.0001, now + idx * 0.07);
      gain.gain.linearRampToValueAtTime(0.05, now + idx * 0.07 + 0.04);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + idx * 0.07 + 1.6);
      
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      
      osc.start(now + idx * 0.07);
      osc.stop(now + idx * 0.07 + 1.7);
    });
  } catch (e) {
    console.error('Startup chime failed:', e);
  }
}

function playTone(frequency, duration, volume = 0.1) {
  if (!audioCtx) return;
  try {
    if (audioCtx.state === 'suspended') {
      audioCtx.resume();
    }
    const osc = audioCtx.createOscillator();
    const gainNode = audioCtx.createGain();
    
    osc.type = 'sine';
    osc.frequency.setValueAtTime(frequency, audioCtx.currentTime);
    
    gainNode.gain.setValueAtTime(volume, audioCtx.currentTime);
    gainNode.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + duration);
    
    osc.connect(gainNode);
    gainNode.connect(audioCtx.destination);
    
    osc.start();
    osc.stop(audioCtx.currentTime + duration);
  } catch (e) {
    console.error('Tone generation failed:', e);
  }
}

// Synthesizes a cybersecurity siren (Klaxon sweep) using pure oscillators
function playSirenAlarm() {
  if (!isAudioAlarmEnabled || isSirenPlaying) return;
  
  if (!audioCtx) {
    // Show user prompt if AudioContext isn't initialized yet
    document.getElementById('audio-init-prompt').style.display = 'block';
    return;
  }

  try {
    if (audioCtx.state === 'suspended') {
      audioCtx.resume();
    }
    
    isSirenPlaying = true;
    sirenGain = audioCtx.createGain();
    sirenGain.gain.setValueAtTime(0.12, audioCtx.currentTime);
    sirenGain.connect(audioCtx.destination);

    // Create dual oscillators for a richer, dissonant alarm sweep
    sirenOsc1 = audioCtx.createOscillator();
    sirenOsc1.type = 'sawtooth';
    sirenOsc1.frequency.setValueAtTime(800, audioCtx.currentTime);
    sirenOsc1.connect(sirenGain);
    sirenOsc1.start();

    sirenOsc2 = audioCtx.createOscillator();
    sirenOsc2.type = 'triangle';
    sirenOsc2.frequency.setValueAtTime(810, audioCtx.currentTime);
    sirenOsc2.connect(sirenGain);
    sirenOsc2.start();

    // Alternate frequency sweep interval (klaxon sound)
    let flip = false;
    sirenInterval = setInterval(() => {
      if (!audioCtx) return;
      const targetFreq = flip ? 980 : 750;
      // Smooth frequency transition
      sirenOsc1.frequency.exponentialRampToValueAtTime(targetFreq, audioCtx.currentTime + 0.35);
      sirenOsc2.frequency.exponentialRampToValueAtTime(targetFreq + 10, audioCtx.currentTime + 0.35);
      flip = !flip;
    }, 380);

    addLogLine('[ALERT] Audio alarm siren systems ACTIVE.', 'critical');
  } catch (e) {
    console.error('Siren synthesis failed:', e);
  }
}

function stopSirenAlarm() {
  if (sirenInterval) {
    clearInterval(sirenInterval);
    sirenInterval = null;
  }
  
  try {
    if (sirenOsc1) {
      sirenOsc1.stop();
      sirenOsc1.disconnect();
      sirenOsc1 = null;
    }
    if (sirenOsc2) {
      sirenOsc2.stop();
      sirenOsc2.disconnect();
      sirenOsc2 = null;
    }
    if (sirenGain) {
      sirenGain.disconnect();
      sirenGain = null;
    }
  } catch (e) {
    // Already cleaned up
  }
  
  isSirenPlaying = false;
  const hazardAlarm = document.getElementById('hazard-alarm');
  if (hazardAlarm) hazardAlarm.classList.remove('active');
}

function toggleAlarmAudio(event) {
  isAudioAlarmEnabled = event.target.checked;
  if (!isAudioAlarmEnabled) {
    stopSirenAlarm();
  }
  addLogLine(`[INFO] Audio Siren Alarm: ${isAudioAlarmEnabled ? 'ENABLED' : 'DISABLED'}`, 'system');
}

// 3. Navigation Controls (Module Switching)
function navigateTo(moduleId) {
  // Stop sirens and calls on navigation change
  stopSirenAlarm();
  if (isCallActive) {
    terminateCallSimulation();
  }

  activeModule = moduleId;
  
  // Highlight navigation item
  const navIds = ['email', 'sms', 'caller', 'interceptor', 'sim', 'urlqr', 'domain', 'history', 'training', 'account'];
  navIds.forEach(id => {
    const navElem = document.getElementById(`nav-${id}`);
    const viewElem = document.getElementById(`view-${id}`);
    if (navElem) navElem.classList.toggle('active', id === moduleId);
    
    // Some views are managed via display inline styles rather than active classes, but active class works if css supports it.
    // However, historically Trust&Verify uses style.display = 'block' vs 'none'
    if (viewElem) {
      viewElem.style.display = id === moduleId ? 'block' : 'none';
      viewElem.classList.toggle('active', id === moduleId);
    }
  });
  
  if (moduleId === 'history') {
    if (window.historyUi) window.historyUi.loadHistory();
  }
  if (moduleId === 'training') {
    if (window.trainingUi) window.trainingUi.renderDashboard();
  }
  if (moduleId === 'account') {
    if (window.accountUi) window.accountUi.refreshAuth();
  }
  
  addLogLine(`[SYSTEM] Switched console panel to: [${moduleId.toUpperCase()}_MATRIX]`, 'system');
}

// Sub-Tab Switch for Email Module
function switchEmailTab(tabId) {
  activeEmailTab = tabId;
  
  document.getElementById('tab-headers-btn').classList.toggle('active', tabId === 'headers');
  document.getElementById('tab-eml-btn').classList.toggle('active', tabId === 'eml');
  document.getElementById('tab-files-btn').classList.toggle('active', tabId === 'files');
  
  document.getElementById('email-tab-headers').classList.toggle('active', tabId === 'headers');
  document.getElementById('email-tab-eml').classList.toggle('active', tabId === 'eml');
  document.getElementById('email-tab-files').classList.toggle('active', tabId === 'files');
  
  addLogLine(`[INFO] Sub-tab navigation focused on: ${tabId.toUpperCase()}`, 'system');
}

// 4. Shared Diagnostics UI Updates
// NOTE: DOM element references are resolved lazily so they are always available
// after DOMContentLoaded, regardless of script-load order.
let _terminalLogs = null;
let _findingsList = null;
let _emptyFindings = null;
let _threatScoreText = null;
let _threatLevelBadge = null;
let _threatVerdictSummary = null;
let _gaugeFillCircle = null;

function getEl(id) {
  return document.getElementById(id);
}

function ensureDOMRefs() {
  if (!_terminalLogs) {
    _terminalLogs = getEl('terminal-logs');
    _findingsList = getEl('findings-list');
    _emptyFindings = getEl('empty-findings');
    _threatScoreText = getEl('threat-score');
    _threatLevelBadge = getEl('threat-level-badge');
    _threatVerdictSummary = getEl('threat-verdict-summary');
    _gaugeFillCircle = getEl('gauge-fill-circle');
  }
}

function addLogLine(text, type = 'system') {
  ensureDOMRefs();
  if (!_terminalLogs) return;
  const line = document.createElement('div');
  line.className = `log-line ${type}`;
  line.textContent = text;
  _terminalLogs.appendChild(line);
  _terminalLogs.scrollTop = _terminalLogs.scrollHeight;
}

function clearTerminal() {
  ensureDOMRefs();
  if (_terminalLogs) _terminalLogs.innerHTML = '';
}

function updateThreatGauge(score, rating) {
  ensureDOMRefs();
  if (!_threatScoreText) return;
  _threatScoreText.textContent = `${score}%`;
  
  // Circumference calculation for r=40 is 251.2
  const offset = 251.2 - (score / 100) * 251.2;
  _gaugeFillCircle.style.strokeDashoffset = offset;
  
  let color = 'var(--accent-cyan)';
  let ratingClass = 'low';
  
  if (score >= 80) {
    color = 'var(--accent-red)';
    ratingClass = 'critical';
    
    // Trigger visual hazard alert overlay & sound siren
    const hazardAlarm = getEl('hazard-alarm');
    if (hazardAlarm) hazardAlarm.classList.add('active');
    playSirenAlarm();
  } else {
    // Stop siren if score drops below 80
    stopSirenAlarm();
    
    if (score >= 50) {
      color = 'var(--accent-red)';
      ratingClass = 'high';
    } else if (score >= 25) {
      color = 'var(--accent-yellow)';
      ratingClass = 'medium';
    } else if (score > 0) {
      color = 'var(--accent-cyan)';
      ratingClass = 'low';
    } else {
      color = 'var(--accent-green)';
      ratingClass = 'safe';
    }
  }
  
  _gaugeFillCircle.style.stroke = color;
  _threatLevelBadge.className = `threat-badge ${ratingClass}`;
  _threatLevelBadge.textContent = rating.toUpperCase();
}

function populateFindings(findings) {
  ensureDOMRefs();
  if (!_findingsList) return;
  _findingsList.innerHTML = '';
  
  if (!findings || findings.length === 0) {
    if (_emptyFindings) {
      _emptyFindings.style.display = 'block';
      _findingsList.appendChild(_emptyFindings);
    }
    return;
  }
  
  if (_emptyFindings) _emptyFindings.style.display = 'none';
  
  findings.forEach((find, index) => {
    const card = document.createElement('div');
    card.className = `finding-card ${find.type === 'danger' ? 'danger' : 'warning'}`;
    
    const title = document.createElement('div');
    title.className = 'finding-title';
    title.textContent = `${find.type === 'danger' ? '⚠️' : '🔔'} ${find.title}`;
    
    const desc = document.createElement('div');
    desc.className = 'finding-desc';
    desc.textContent = find.description || find.message || find.explanation || 'No description provided.';
    
    card.appendChild(title);
    card.appendChild(desc);
    
    // Phase 1/2: Add detailed view button if structured data is present
    if (find.explanation || find.evidence || find.recommendation || find.description) {
      const btn = document.createElement('button');
      btn.className = 'btn-finding-detail';
      btn.textContent = 'View Details';
      btn.onclick = () => openFindingDetails(find);
      card.appendChild(btn);
    }
    
    _findingsList.appendChild(card);
  });
}

function openFindingDetails(finding) {
  const modal = document.getElementById('intel-modal');
  if (!modal) return;
  
  document.getElementById('intel-modal-title').textContent = `THREAT_INTEL://${finding.severity || 'WARNING'}`;
  document.getElementById('intel-modal-badge').textContent = finding.category || 'ANALYSIS';
  document.getElementById('intel-modal-heading').textContent = finding.title;
  document.getElementById('intel-modal-desc').textContent = finding.description || finding.explanation || finding.message;
  
  const codeBlock = document.getElementById('intel-modal-code');
  if (finding.evidence) {
    codeBlock.textContent = finding.evidence;
    codeBlock.parentElement.style.display = 'block';
  } else {
    codeBlock.parentElement.style.display = 'none';
  }
  
  const mitiBlock = document.getElementById('intel-modal-mitigation');
  if (finding.recommendation) {
    mitiBlock.textContent = finding.recommendation;
    mitiBlock.parentElement.style.display = 'block';
  } else {
    mitiBlock.parentElement.style.display = 'none';
  }
  
  modal.classList.add('active');
}

function closeIntelligenceModal() {
  const modal = document.getElementById('intel-modal');
  if (modal) modal.classList.remove('active');
}

function populateParsedHeaders(parsedHeaders) {
  const tbody = document.getElementById('parsed-headers-tbody');
  const btn = document.getElementById('btn-view-headers');
  if (!tbody || !btn) return;
  
  tbody.innerHTML = '';
  
  if (!parsedHeaders || parsedHeaders.length === 0) {
    btn.style.display = 'none';
    return;
  }
  
  btn.style.display = 'block';
  
  parsedHeaders.forEach(h => {
    const tr = document.createElement('tr');
    
    const tdName = document.createElement('td');
    tdName.textContent = (h.name || '').toUpperCase();
    tdName.style.color = 'var(--accent-cyan)';
    
    const tdVal = document.createElement('td');
    tdVal.textContent = h.value;
    
    const tdRaw = document.createElement('td');
    tdRaw.textContent = h.raw || '';
    tdRaw.style.opacity = '0.7';
    tdRaw.style.fontSize = '0.9em';
    tdRaw.style.whiteSpace = 'pre-wrap';
    
    tr.appendChild(tdName);
    tr.appendChild(tdVal);
    tr.appendChild(tdRaw);
    tbody.appendChild(tr);
  });
}

function openHeadersModal() {
  const modal = document.getElementById('headers-modal');
  if (modal) modal.classList.add('active');
}

function closeHeadersModal() {
  const modal = document.getElementById('headers-modal');
  if (modal) modal.classList.remove('active');
}

// 5. EMAIL MODULE EXECUTION (Existing Code base)
const TEMPLATES = {
  spoofed_paypal: `From: "PayPal Account Security" <verification-department@resolve-paypal-invoice.com>
To: recipient@userinbox.org
Subject: CRITICAL: Your account has been temporarily restricted!
Date: Fri, 19 Jun 2026 14:03:00 +0000
Message-ID: <847239-paypal-resolve@secure-server.com>
Received: from mail.resolve-paypal-invoice.com (192.0.2.112) by mx.inboxgateway.net;
Received-SPF: softfail (inboxgateway.net: domain of resolve-paypal-invoice.com does not designate 192.0.2.112 as permitted sender)
Authentication-Results: mx.inboxgateway.net; dkim=fail; spf=softfail; dmarc=fail`,

  spf_fail: `From: "Microsoft Security Center" <no-reply@microsoft.com>
To: internal-employee@yourcompany.com
Subject: Warning: Critical system update required immediately
Date: Fri, 19 Jun 2026 10:20:15 +0100
Received: from malicious-relay.phishing-infrastructure.net (203.0.113.88) by exchange.yourcompany.com;
Received-SPF: fail (exchange.yourcompany.com: domain of microsoft.com does not designate 203.0.113.88 as authorized sender)
Authentication-Results: exchange.yourcompany.com; dkim=fail header.i=@microsoft.com; dmarc=fail`,

  safe_corporate: `From: "Google Workspace Team" <workspace-noreply@google.com>
To: account-owner@gmail.com
Subject: Monthly usage report and security summary
Date: Fri, 19 Jun 2026 09:12:12 -0700
Message-ID: <gws-summary-294829@mail.google.com>
Received: from mail-sender.google.com (209.85.220.41) by mx.google.com;
Received-SPF: pass (google.com: domain of workspace-noreply@google.com designates 209.85.220.41 as permitted sender)
Authentication-Results: mx.google.com; dkim=pass header.i=@google.com; dmarc=pass`
};

function loadPreset(key) {
  if (TEMPLATES[key]) {
    document.getElementById('headers-input').value = TEMPLATES[key];
    addLogLine(`[INFO] Loaded Email header preset: "${key.replace('_', ' ').toUpperCase()}"`, 'success');
  }
}

async function runHeaderAnalysis() {
  const headers = document.getElementById('headers-input').value;
  if (!headers || headers.trim() === '') {
    addLogLine('[ERROR] No email headers detected. Scanning canceled.', 'critical');
    return;
  }

  // Ensure AudioContext is ready (prompt if not)
  initAudioContext();

  clearTerminal();
  addLogLine(`[SYSTEM] Starting Trust & Verify header parsing engine...`, 'system');
  addLogLine(`[SYSTEM] Accessing DNS SPF/DKIM verification endpoints...`, 'system');
  
  const scanBtn = document.getElementById('btn-run-headers');
  scanBtn.setAttribute('disabled', 'true');
  
  setTimeout(() => {
    if (typeof window.analyzeHeaders === 'function') {
      const results = window.analyzeHeaders(headers);
      
      results.logs.forEach(log => {
        let type = 'success';
        if (log.includes('[CRITICAL]')) type = 'critical';
        else if (log.includes('[WARN]')) type = 'warn';
        addLogLine(log, type);
      });
      
      updateThreatGauge(results.score, results.threatLevel);
      populateFindings(results.indicators || results.details || results.findings);
      populateParsedHeaders(results.parsedHeaders);
      
      let verdict = 'Email inspection complete. No critical structural anomalies detected.';
      if (results.score >= 80) {
        verdict = 'CRITICAL ALARM: Verified sender spoofing signature!';
      } else if (results.score >= 50) {
        verdict = 'HIGH WARNING: SPF/DKIM failed. High risk of phishing spoof.';
      } else if (results.score >= 25) {
        verdict = 'MEDIUM WARNING: Authentication records are missing or unconfigured.';
      }
      if (_threatVerdictSummary) _threatVerdictSummary.textContent = verdict;
      
      // Save History
      if (window.historyManager && window.historyStore) {
        historyManager.createScanRecord('EMAIL_THREAT_SCANNER', 'raw_headers', {
          score: results.score,
          severity: results.threatLevel,
          verdict: verdict,
          indicators: results.indicators || results.details || results.findings || []
        }).then(record => historyStore.saveScan(record))
          .then(() => addLogLine(`[SYSTEM] Scan saved to history.`, 'success'))
          .catch(e => addLogLine(`[WARN] Could not save history: ${e.message}`, 'warn'));
      }
      
      scanBtn.removeAttribute('disabled');
      addLogLine(`[SUCCESS] Email header analysis complete. Threat Score: ${results.score}%`, 'success');
    } else {
      addLogLine('[ERROR] Header parser module missing.', 'critical');
      scanBtn.removeAttribute('disabled');
    }
  }, 600);
}

// EML File Handler
const emlDropzone = document.getElementById('eml-dropzone');
if (emlDropzone) {
  ['dragenter', 'dragover'].forEach(eventName => {
    emlDropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      emlDropzone.classList.add('dragover');
    }, false);
  });
  ['dragleave', 'drop'].forEach(eventName => {
    emlDropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      emlDropzone.classList.remove('dragover');
    }, false);
  });
  emlDropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) selectEml(files[0]);
  });
}

function handleEmlSelect(event) {
  const files = event.target.files;
  if (files.length > 0) selectEml(files[0]);
}

function selectEml(file) {
  selectedEml = file;
  document.getElementById('selected-eml-name').textContent = file.name;
  document.getElementById('selected-eml-size').textContent = formatBytes(file.size);
  document.getElementById('eml-info-card').style.display = 'flex';
  document.getElementById('btn-run-eml').removeAttribute('disabled');
  addLogLine(`[INFO] EML message queued for analysis: ${file.name}`, 'success');
}

function clearSelectedEml() {
  selectedEml = null;
  document.getElementById('eml-input').value = '';
  document.getElementById('eml-info-card').style.display = 'none';
  document.getElementById('btn-run-eml').setAttribute('disabled', 'true');
  addLogLine(`[INFO] EML queue cleared.`, 'system');
}

async function runEmlScan() {
  if (!selectedEml) return;

  initAudioContext();
  clearTerminal();
  const scanBtn = document.getElementById('btn-run-eml');
  scanBtn.setAttribute('disabled', 'true');
  addLogLine(`[SYSTEM] Transmitting .EML payload to backend analysis engine...`, 'system');

  const formData = new FormData();
  formData.append('emlFile', selectedEml);

  try {
    const response = await fetch('/api/scan-eml', {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      let errText = 'Server error';
      try {
        const errJson = await response.json();
        errText = errJson.error || errText;
      } catch (e) {}
      throw new Error(errText);
    }

    const results = await response.json();
    
    // Replay logs
    if (results.logs && results.logs.length > 0) {
      results.logs.forEach(log => {
        let type = 'success';
        if (log.includes('[CRITICAL]')) type = 'critical';
        else if (log.includes('[WARN]')) type = 'warn';
        addLogLine(log, type);
      });
    }

    updateThreatGauge(results.score || 0, results.threatLevel || 'Unknown');
    populateParsedHeaders(results.parsedHeaders);
    
    // Combine header findings with attachment findings
    const allFindings = [...(results.findings || [])];
    if (results.attachments) {
      results.attachments.forEach(att => {
        if (att.findings) {
          allFindings.push(...att.findings);
        }
      });
    }
    populateFindings(allFindings);

    let verdict = 'EML analysis complete.';
    if (results.score >= 80) {
      verdict = 'CRITICAL ALARM: Malicious indicators detected in EML.';
    } else if (results.score >= 50) {
      verdict = 'HIGH WARNING: EML contains suspicious indicators or attachments.';
    }
    if (_threatVerdictSummary) _threatVerdictSummary.textContent = verdict;
    
    // Phase 1 EML UI Rendering
    if (typeof populateEmlResults === 'function') {
      populateEmlResults(results);
    }
    
    // History
    if (window.historyManager && window.historyStore) {
      try {
        const record = await historyManager.createScanRecord('EMAIL_THREAT_SCANNER', selectedEml.name || 'eml_file', {
          score: results.score,
          severity: results.threatLevel,
          verdict: verdict,
          indicators: allFindings
        });
        await historyStore.saveScan(record);
        addLogLine(`[SYSTEM] Scan saved to history.`, 'success');
      } catch(e) {
        addLogLine(`[WARN] Could not save history: ${e.message}`, 'warn');
      }
    }
    
    addLogLine(`[SUCCESS] EML backend scan complete. Threat Score: ${results.score || 0}%`, 'success');
  } catch (e) {
    addLogLine(`[ERROR] EML scan failed: ${e.message}`, 'critical');
  } finally {
    scanBtn.removeAttribute('disabled');
  }
}

}

// EML UI Rendering Logic
function populateEmlResults(results) {
  const container = document.getElementById('eml-results-container');
  if (!container) return;
  container.style.display = 'block';

  // 1. Message Envelope
  const msgBox = document.getElementById('eml-res-message');
  if (msgBox) {
    msgBox.innerHTML = '';
    const m = results.message || {};
    const fields = [
      { k: 'From', v: m.from },
      { k: 'To', v: m.to },
      { k: 'CC', v: m.cc },
      { k: 'Reply-To', v: m.replyTo },
      { k: 'Return-Path', v: m.returnPath },
      { k: 'Subject', v: m.subject },
      { k: 'Date', v: m.date }
    ];
    fields.forEach(f => {
      if (f.v) {
        msgBox.innerHTML += `<div class="eml-data-row"><span class="eml-data-label">${f.k}</span><span class="eml-data-value">${escapeHtml(f.v)}</span></div>`;
      }
    });
  }

  // 2. Authentication
  const authBox = document.getElementById('eml-res-auth');
  if (authBox) {
    authBox.innerHTML = '';
    const a = results.authentication || {};
    const authFields = [
      { k: 'SPF', v: a.spf },
      { k: 'DKIM', v: a.dkim },
      { k: 'DMARC', v: a.dmarc }
    ];
    authFields.forEach(f => {
      let colorClass = 'safe';
      if (f.v === 'fail') colorClass = 'danger';
      else if (f.v === 'softfail' || f.v === 'neutral') colorClass = 'warning';
      
      authBox.innerHTML += `<div class="eml-data-row"><span class="eml-data-label">${f.k}</span><span class="eml-data-value ${colorClass}">${escapeHtml(f.v || 'none')}</span></div>`;
    });
  }

  // 3. Routing
  const routingBox = document.getElementById('eml-res-routing');
  if (routingBox) {
    routingBox.innerHTML = '';
    const r = results.routing || {};
    routingBox.innerHTML += `<div class="eml-data-row" style="grid-column: span 2;"><span class="eml-data-label">Originating IP</span><span class="eml-data-value">${escapeHtml(r.originatingIP || 'Unknown')}</span></div>`;
    if (r.hops && r.hops.length > 0) {
      r.hops.forEach((h, i) => {
        routingBox.innerHTML += `<div class="eml-data-row" style="grid-column: span 2;"><span class="eml-data-label">Hop ${i + 1}</span><span class="eml-data-value">From: ${escapeHtml(h.from || '?')} | By: ${escapeHtml(h.by || '?')} | IP: ${escapeHtml(h.ip || '?')}</span></div>`;
      });
    }
  }

  // 4. Links
  const linksBox = document.getElementById('eml-res-links');
  if (linksBox) {
    linksBox.innerHTML = '';
    const l = results.links || [];
    if (l.length === 0) {
      linksBox.innerHTML = '<span style="color:#aaa; font-size:12px;">No links found.</span>';
    } else {
      l.forEach(link => {
        const btn = document.createElement('span');
        btn.className = 'eml-link-item';
        btn.textContent = link.length > 60 ? link.substring(0, 57) + '...' : link;
        btn.onclick = () => openSafeLinkModal(link);
        linksBox.appendChild(btn);
      });
    }
  }

  // 5. Attachments
  const attBox = document.getElementById('eml-res-attachments');
  if (attBox) {
    attBox.innerHTML = '';
    const atts = results.attachments || [];
    if (atts.length === 0) {
      attBox.innerHTML = '<span style="color:#aaa; font-size:12px;">No attachments found.</span>';
    } else {
      atts.forEach(att => {
        const color = (att.riskCategory === 'Critical' || att.riskCategory === 'High') ? 'text-danger' : 'text-success';
        attBox.innerHTML += `<div class="eml-attachment-item">
          <div style="font-weight:bold; margin-bottom:5px;">${escapeHtml(att.filename)} <span class="badge ${color}">[${escapeHtml(att.riskCategory)}]</span></div>
          <div style="font-size:12px; color:#aaa;">Type: ${escapeHtml(att.contentType)} | Size: ${formatBytes(att.size)}</div>
          <div style="font-size:12px; color:#aaa; font-family: monospace;">SHA-256: ${escapeHtml(att.hash)}</div>
        </div>`;
      });
    }
  }
}

function openSafeLinkModal(urlStr) {
  const modal = document.getElementById('safe-link-modal');
  if (!modal) return;
  
  let host = '-', protocol = '-', port = '-', pathname = '-', search = '-', hash = '-';
  try {
    const u = new URL(urlStr);
    host = u.hostname;
    protocol = u.protocol;
    port = u.port || (protocol === 'https:' ? '443' : '80');
    pathname = u.pathname;
    search = u.search;
    hash = u.hash;
  } catch (e) {
    host = 'Invalid URL format';
  }

  document.getElementById('sl-url').textContent = urlStr;
  document.getElementById('sl-host').textContent = host;
  document.getElementById('sl-protocol').textContent = protocol;
  document.getElementById('sl-port').textContent = port;
  document.getElementById('sl-path').textContent = pathname;
  document.getElementById('sl-query').textContent = search;
  document.getElementById('sl-fragment').textContent = hash;
  
  modal.classList.add('active');
}

function closeSafeLinkModal() {
  const modal = document.getElementById('safe-link-modal');
  if (modal) modal.classList.remove('active');
}

function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return String(unsafe)
       .replace(/&/g, "&amp;")
       .replace(/</g, "&lt;")
       .replace(/>/g, "&gt;")
       .replace(/"/g, "&quot;")
       .replace(/'/g, "&#039;");
}

// Email Attachment Handler
const dropzone = document.getElementById('file-dropzone');
['dragenter', 'dragover'].forEach(eventName => {
  dropzone.addEventListener(eventName, (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  }, false);
});
['dragleave', 'drop'].forEach(eventName => {
  dropzone.addEventListener(eventName, (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
  }, false);
});
dropzone.addEventListener('drop', (e) => {
  const files = e.dataTransfer.files;
  if (files.length > 0) selectFile(files[0]);
});

function handleFileSelect(event) {
  const files = event.target.files;
  if (files.length > 0) selectFile(files[0]);
}

function selectFile(file) {
  selectedFile = file;
  simulatedFileData = null;
  document.getElementById('selected-file-name').textContent = file.name;
  document.getElementById('selected-file-size').textContent = formatBytes(file.size);
  document.getElementById('file-info-card').style.display = 'flex';
  document.getElementById('btn-run-files').removeAttribute('disabled');
  addLogLine(`[INFO] Attachment queued for scan: ${file.name}`, 'success');
}

function clearSelectedFile() {
  selectedFile = null;
  simulatedFileData = null;
  document.getElementById('file-input').value = '';
  document.getElementById('file-info-card').style.display = 'none';
  document.getElementById('btn-run-files').setAttribute('disabled', 'true');
  addLogLine(`[INFO] File queue cleared.`, 'system');
}

function simulateFile(filename, hash, content) {
  simulatedFileData = { filename, hash, content };
  selectedFile = null;
  document.getElementById('selected-file-name').textContent = filename + " [SIMULATED]";
  document.getElementById('selected-file-size').textContent = hash ? "Hash-defined" : "Content-defined";
  document.getElementById('file-info-card').style.display = 'flex';
  document.getElementById('btn-run-files').removeAttribute('disabled');
  addLogLine(`[INFO] Simulated file payload loaded: ${filename}`, 'warn');
}

async function runFileScan() {
  initAudioContext();
  clearTerminal();
  const scanBtn = document.getElementById('btn-run-files');
  scanBtn.setAttribute('disabled', 'true');
  addLogLine(`[SYSTEM] Initializing binary attachment scanner...`, 'system');

  const processResults = async (results) => {
    results.logs.forEach(log => {
      let type = 'success';
      if (log.includes('[CRITICAL]')) type = 'critical';
      else if (log.includes('[WARN]')) type = 'warn';
      addLogLine(log, type);
    });

    let combinedIndicators = results.indicators || results.details || [];
    
    // Save Initial Local History
    let scanId = null;
    if (window.historyManager && window.historyStore) {
      try {
        const record = await historyManager.createScanRecord('FILE_ATTACHMENTS', results.filename || 'unknown_file', results);
        scanId = await historyStore.saveScan(record);
      } catch(e) {}
    }

    const useTi = document.getElementById('file-ti-toggle')?.checked;
    if (useTi && results.hash) {
      const tiIndicators = await executeThreatIntel(results.hash, 'HASH');
      if (tiIndicators && tiIndicators.length > 0) {
        combinedIndicators = [...combinedIndicators, ...tiIndicators];
        results.score = Math.min(100, results.score + (tiIndicators.length * 20));
        results.indicators = combinedIndicators;
        
        if (scanId && window.historyStore && window.lastTiResult) {
          try {
            await historyStore.updateScan(scanId, {
               result: results,
               threatIntelligence: window.lastTiResult
            });
          } catch(e) {}
        }
      }
    } else {
      document.getElementById('threat-intel-results').style.display = 'none';
    }

    updateThreatGauge(results.score, results.threatLevel || (results.score > 75 ? 'Critical' : 'Low'));
    populateFindings(combinedIndicators);

    let verdict = 'File scanning complete. Binary structure matches safe signatures.';
    if (results.score >= 80) {
      verdict = 'CRITICAL WARNING: Known ransomware hash match or malicious VBA macro downloader verified!';
    } else if (results.score >= 50) {
      verdict = 'HIGH WARNING: Dangerous extension or active scripting indicators found.';
    } else if (results.score >= 25) {
      verdict = 'MEDIUM WARNING: Embedded archives or macros present risk.';
    }
    if (_threatVerdictSummary) _threatVerdictSummary.textContent = verdict;
    scanBtn.removeAttribute('disabled');
    addLogLine(`[SUCCESS] File check complete. Threat Score: ${results.score}%`, 'success');
  };

  if (simulatedFileData) {
    setTimeout(() => {
      if (typeof window.analyzeFile === 'function') {
        const res = window.analyzeFile(simulatedFileData.filename, simulatedFileData.content, simulatedFileData.hash);
        processResults(res);
      }
    }, 600);
    return;
  }

  if (!selectedFile) return;
  try {
    addLogLine(`[INFO] Generating SHA-256 signature hash...`, 'system');
    const arrayBuffer = await selectedFile.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const fileHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    const fileText = await selectedFile.text();
    if (typeof window.analyzeFile === 'function') {
      const res = window.analyzeFile(selectedFile.name, fileText, fileHash);
      processResults(res);
    }
  } catch (e) {
    addLogLine(`[ERROR] File scanning failure: ${e.message}`, 'critical');
    scanBtn.removeAttribute('disabled');
  }
}

// 6. SMS MODULE EXECUTION
const SMS_TEMPLATES = {
  phishing_alert: `ChaseAlert: Suspicious login detected on your mobile account. If this was NOT you, immediately lock your credit profile at: https://bit.ly/chase-mobile-sec-x`,
  cyberbully: `you are a pathetic loser. everyone at school hates you. go die, do us a favor and kill yourself, or else I will post your pictures online`,
  safe_text: `Hey, just checking in to see if you wanted to grab lunch today? I'll be near the office around 12:30.`
};

function loadSMSPreset(key) {
  if (SMS_TEMPLATES[key]) {
    document.getElementById('sms-input').value = SMS_TEMPLATES[key];
    addLogLine(`[INFO] Loaded SMS preset: "${key.toUpperCase()}"`, 'success');
  }
}

function runSMSAnalysis() {
  const text = document.getElementById('sms-input').value;
  if (!text || text.trim() === '') {
    addLogLine('[ERROR] No SMS content provided.', 'critical');
    return;
  }

  initAudioContext();
  clearTerminal();
  addLogLine(`[SYSTEM] Active decrypting SMS content...`, 'system');

  const scanBtn = document.getElementById('btn-run-sms');
  scanBtn.setAttribute('disabled', 'true');

  setTimeout(() => {
    if (typeof window.analyzeSMS === 'function') {
      const results = window.analyzeSMS(text);
      
      results.logs.forEach(log => {
        let type = 'success';
        if (log.includes('[CRITICAL]')) type = 'critical';
        else if (log.includes('[WARN]')) type = 'warn';
        addLogLine(log, type);
      });

      updateThreatGauge(results.score, results.threatLevel);
      populateFindings(results.indicators || results.details);

      let verdict = 'SMS scan complete. No critical threat signatures found.';
      if (results.score >= 80) {
        verdict = 'CRITICAL ALERT: Detected highly abusive cyberbullying or urgent phishing redirection!';
      } else if (results.score >= 50) {
        verdict = 'HIGH WARNING: Contains coercive threats, insults, or external links.';
      } else if (results.score >= 25) {
        verdict = 'MEDIUM WARNING: Obfuscated links or brand references found.';
      }
      if (_threatVerdictSummary) _threatVerdictSummary.textContent = verdict;

      // Save History
      if (window.historyManager && window.historyStore) {
        historyManager.createScanRecord('SMS_SHIELD', text, {
          score: results.score,
          severity: results.threatLevel,
          verdict: verdict,
          indicators: results.indicators || results.details || []
        }).then(record => historyStore.saveScan(record))
          .then(() => addLogLine(`[SYSTEM] Scan saved to history.`, 'success'))
          .catch(e => addLogLine(`[WARN] Could not save history: ${e.message}`, 'warn'));
      }

      scanBtn.removeAttribute('disabled');
      addLogLine(`[SUCCESS] SMS check complete. Rating: ${results.threatLevel}`, 'success');
    } else {
      addLogLine('[ERROR] SMS analysis module missing.', 'critical');
      scanBtn.removeAttribute('disabled');
    }
  }, 600);
}

// 7. CALLER ID SCANNER MODULE
function loadPhonePreset(number) {
  document.getElementById('phone-input').value = number;
  addLogLine(`[INFO] Loaded Phone number preset: ${number}`, 'success');
}

function runPhoneScan() {
  const number = document.getElementById('phone-input').value;
  
  // Hide details card at start of new scan
  document.getElementById('caller-profile-card').style.display = 'none';

  if (!number || number.trim() === '') {
    addLogLine('[ERROR] No phone number entered.', 'critical');
    return;
  }

  initAudioContext();
  clearTerminal();
  addLogLine(`[SYSTEM] Starting global blacklist query for number: ${number}`, 'system');

  const scanBtn = document.getElementById('btn-run-phone');
  scanBtn.setAttribute('disabled', 'true');

  setTimeout(() => {
    if (typeof window.analyzePhoneNumber === 'function') {
      const results = window.analyzePhoneNumber(number);

      results.logs.forEach(log => {
        let type = 'success';
        if (log.includes('[CRITICAL]')) type = 'critical';
        else if (log.includes('[WARN]')) type = 'warn';
        addLogLine(log, type);
      });

      updateThreatGauge(results.score, results.threatLevel);
      populateFindings(results.indicators || results.details);

      let verdict = 'Caller lookup complete. Number shows clean reputation history.';
      if (results.score >= 80) {
        verdict = 'CRITICAL WARNING: Phone number is verified in the cyber fraud spoofing blacklist!';
      } else if (results.score >= 50) {
        verdict = 'HIGH WARNING: VoIP toll-free prefix. High fraud correlation.';
      } else if (results.score >= 25) {
        verdict = 'MEDIUM WARNING: Malformed length or routing details.';
      }
      if (_threatVerdictSummary) _threatVerdictSummary.textContent = verdict;

      // Populate and display Caller Profile Details Card
      if (results.callerProfile) {
        const profile = results.callerProfile;
        document.getElementById('caller-avatar').textContent = profile.avatar;
        document.getElementById('caller-profile-name').textContent = profile.name;
        document.getElementById('caller-profile-type').textContent = profile.type;
        
        const statusBadge = document.getElementById('caller-profile-status');
        statusBadge.textContent = profile.status;
        statusBadge.className = `profile-status-badge ${profile.statusClass}`;
        
        document.getElementById('caller-detail-number').textContent = profile.number;
        document.getElementById('caller-detail-carrier').textContent = profile.carrier;
        document.getElementById('caller-detail-location').textContent = profile.location;
        document.getElementById('caller-detail-reports').textContent = `${profile.reports} reports`;
        document.getElementById('caller-detail-email').textContent = profile.email;
        document.getElementById('caller-profile-desc').textContent = profile.description;
        
        document.getElementById('caller-profile-card').style.display = 'flex';
      }

      // Save History
      if (window.historyManager && window.historyStore) {
        historyManager.createScanRecord('PHONE_SCANNER', number, {
          score: results.score,
          severity: results.threatLevel,
          verdict: verdict,
          indicators: results.indicators || results.details || []
        }).then(record => historyStore.saveScan(record))
          .then(() => addLogLine(`[SYSTEM] Scan saved to history.`, 'success'))
          .catch(e => addLogLine(`[WARN] Could not save history: ${e.message}`, 'warn'));
      }

      scanBtn.removeAttribute('disabled');
      addLogLine(`[SUCCESS] Caller query complete. Rating: ${results.threatLevel}`, 'success');
    } else {
      addLogLine('[ERROR] Caller analyzer module missing.', 'critical');
      scanBtn.removeAttribute('disabled');
    }
  }, 600);
}

// 8. AI CALL INTERCEPTOR SIMULATOR MODULE
function selectScenario(scenKey) {
  if (isCallActive) return; // Prevent changing during active call
  currentScenario = scenKey;
  
  const scens = ['irs', 'bank', 'family'];
  scens.forEach(s => {
    document.getElementById(`scen-${s}`).classList.toggle('active', s === scenKey);
  });
  
  if (window.INTERCEPTOR_SCENARIOS && window.INTERCEPTOR_SCENARIOS[scenKey]) {
    const details = window.INTERCEPTOR_SCENARIOS[scenKey];
    addLogLine(`[INFO] Scenario updated: "${details.title}"`, 'system');
  }
}

function startCallSimulation() {
  if (isCallActive) return;
  initAudioContext();
  stopSirenAlarm();
  
  const data = window.INTERCEPTOR_SCENARIOS ? window.INTERCEPTOR_SCENARIOS[currentScenario] : null;
  if (!data) {
    addLogLine('[ERROR] Call scenarios configuration not loaded.', 'critical');
    return;
  }

  isCallActive = true;
  callStepIdx = 0;
  callDuration = 0;
  callThreatScore = 0;
  
  // Clear previous outputs
  document.getElementById('call-transcript-feed').innerHTML = '';
  clearTerminal();
  
  // Toggle simulation UI buttons
  document.getElementById('btn-initiate-call').style.display = 'none';
  document.getElementById('btn-terminate-call').style.display = 'block';
  document.getElementById('live-call-box').style.display = 'block';

  // Set header metadata in call pane
  document.getElementById('interceptor-title').textContent = data.title.toUpperCase();
  document.getElementById('interceptor-number').textContent = `CALLING FROM: ${data.number}`;
  document.getElementById('interceptor-timer').textContent = '00:00';

  addLogLine(`[INTERCEPT] Incoming call connection routing from: ${data.number}...`, 'warn');
  addLogLine(`[INTERCEPT] Voice biometric filter locked. intercepting call...`, 'system');

  // Start call timer
  callTimerInterval = setInterval(() => {
    callDuration++;
    const mins = Math.floor(callDuration / 60).toString().padStart(2, '0');
    const secs = (callDuration % 60).toString().padStart(2, '0');
    document.getElementById('interceptor-timer').textContent = `${mins}:${secs}`;
  }, 1000);

  // Play a standard dual-frequency telephone ring sound locally
  playTone(440, 0.4, 0.05);
  setTimeout(() => playTone(480, 0.4, 0.05), 100);

  // Start dialogue playback sequence
  callStepTimeout = setTimeout(playNextCallStep, 1000);
}

function playNextCallStep() {
  const data = window.INTERCEPTOR_SCENARIOS ? window.INTERCEPTOR_SCENARIOS[currentScenario] : null;
  if (!data || !isCallActive) return;

  if (callStepIdx < data.script.length) {
    const step = data.script[callStepIdx];
    const feed = document.getElementById('call-transcript-feed');
    
    // Create dialogue bubble UI element
    const bubble = document.createElement('div');
    bubble.className = `bubble ${step.speaker}`;
    bubble.innerHTML = `<strong>${step.speaker === 'caller' ? '📞 CALLER' : '🤖 AI ASSISTANT'}:</strong> ${step.text}`;
    
    feed.appendChild(bubble);
    feed.scrollTop = feed.scrollHeight;

    // Simulate analysis updates as call progresses
    if (step.speaker === 'caller') {
      // In caller turns, play low-pitched caller tone & increase threat readings
      playTone(280, 0.15, 0.04);
      
      // Calculate dynamic mock score increments
      if (currentScenario === 'irs') {
        callThreatScore = Math.min((callStepIdx + 1) * 34, 100);
      } else if (currentScenario === 'bank') {
        callThreatScore = Math.min((callStepIdx + 1) * 34, 100);
      } else {
        callThreatScore = Math.min((callStepIdx + 1) * 34, 95);
      }

      addLogLine(`[SCANNER] Call content check: Urgency keywords verified. Threat score updated: ${callThreatScore}%`, 'warn');
      updateThreatGauge(callThreatScore, callThreatScore >= 80 ? 'Critical' : 'High');
    } else {
      // In AI turns, play high-pitched clean electronic tone
      playTone(520, 0.1, 0.05);
      addLogLine(`[ASSISTANT] Probing caller identity. Prompting verification details...`, 'system');
    }

    callStepIdx++;
    
    // Set delay for next bubble
    const delay = step.text.length * 28 + 1000;
    callStepTimeout = setTimeout(playNextCallStep, delay);
  } else {
    // Call dialogue finished
    completeCallSimulation();
  }
}

function completeCallSimulation() {
  // Clear timers
  if (callTimerInterval) {
    clearInterval(callTimerInterval);
    callTimerInterval = null;
  }
  
  addLogLine(`[SUCCESS] AI Interception completed. Call channel disconnected.`, 'success');
  addLogLine(`[SYSTEM] Compiling phone scam threat profile log...`, 'system');

  const data = window.INTERCEPTOR_SCENARIOS[currentScenario];
  
  // Update gauge and findings card
  updateThreatGauge(callThreatScore, callThreatScore >= 80 ? 'Critical' : 'High');

  const findings = [];
  if (callThreatScore >= 80) {
    findings.push({
      type: 'danger',
      title: 'Scam Robocall Identified',
      message: `Verified scam pattern matching profile: "${data.title}". Urgent monetary demands or OTP passcodes harvested during transmission.`
    });
  }

  populateFindings(findings);
  if (_threatVerdictSummary) _threatVerdictSummary.textContent = `Call Intercepted. AI Assistant successfully blocked scam execution. Final threat score: ${callThreatScore}%.`;

  // Toggle buttons
  document.getElementById('btn-initiate-call').style.display = 'block';
  document.getElementById('btn-terminate-call').style.display = 'none';
  isCallActive = false;
}

function terminateCallSimulation() {
  if (callTimerInterval) clearInterval(callTimerInterval);
  if (callStepTimeout) clearTimeout(callStepTimeout);
  
  stopSirenAlarm();
  
  document.getElementById('call-transcript-feed').innerHTML = '';
  document.getElementById('live-call-box').style.display = 'none';
  document.getElementById('btn-initiate-call').style.display = 'block';
  document.getElementById('btn-terminate-call').style.display = 'none';
  
  isCallActive = false;
  updateThreatGauge(0, 'Safe');
  populateFindings([]);
  
  addLogLine(`[INTERCEPT] Transmission channel aborted by operator.`, 'critical');
}

// 9. SIM & DEVICE SECURITY REGISTRY CONTROLLER
let currentWizardStep = 1;
let activeSIMPreset = 'verizon_5g';

function initSIMState() {
  if (!window.simRegistryEngine) return;
  const evaluation = window.simRegistryEngine.evaluateSIMSecurity();
  applySIMEvaluation(evaluation, false);
}

function applySIMEvaluation(res, logToTerminal = true) {
  const currentSIM = res.currentSIM;
  const boundProfile = res.boundProfile;
  const status = res.status;

  // 1. Update Top OEM Header Bar
  const carrierText = document.getElementById('oem-carrier-text');
  const carrierDot = document.getElementById('oem-carrier-dot');
  const bindingPill = document.getElementById('oem-binding-pill');
  const headerRegBtn = document.getElementById('btn-header-register');

  if (carrierText && currentSIM) {
    carrierText.textContent = `SIM: ${currentSIM.carrier.toUpperCase()} (${currentSIM.phoneNumber})`;
  } else if (carrierText) {
    carrierText.textContent = 'SIM: NO SIM DETECTED';
  }

  if (bindingPill) {
    if (status === 'REGISTERED_SECURE') {
      bindingPill.className = 'binding-pill success';
      bindingPill.textContent = '🔒 SIM REGISTERED & BOUND';
      if (headerRegBtn) headerRegBtn.style.display = 'none';
      if (carrierDot) carrierDot.className = 'sim-carrier-dot online';
    } else if (status === 'SIM_SWAP_ATTACK') {
      bindingPill.className = 'binding-pill danger';
      bindingPill.textContent = '🚨 UNAUTHORIZED SIM SWAP!';
      if (headerRegBtn) {
        headerRegBtn.style.display = 'inline-flex';
        headerRegBtn.innerHTML = '<span>⚠️ RE-VERIFY SIM KEY</span>';
      }
      if (carrierDot) carrierDot.className = 'sim-carrier-dot compromised';
    } else if (status === 'NO_SIM') {
      bindingPill.className = 'binding-pill warning';
      bindingPill.textContent = '⚠️ NO SIM INSERTED';
      if (headerRegBtn) headerRegBtn.style.display = 'none';
      if (carrierDot) carrierDot.className = 'sim-carrier-dot offline';
    } else {
      // Unregistered
      bindingPill.className = 'binding-pill warning';
      bindingPill.textContent = '⚠️ REGISTRATION PENDING';
      if (headerRegBtn) {
        headerRegBtn.style.display = 'inline-flex';
        headerRegBtn.innerHTML = '<span>🔒 REGISTER & BIND SIM</span>';
      }
      if (carrierDot) carrierDot.className = 'sim-carrier-dot online';
    }
  }

  // 2. Update View SIM Module Elements
  if (currentSIM) {
    const elCarrier = document.getElementById('sim-card-carrier');
    const elPhone = document.getElementById('sim-card-phone');
    const elIccid = document.getElementById('sim-card-iccid');
    const elImsi = document.getElementById('sim-card-imsi');
    const elEnclave = document.getElementById('sim-card-enclave');
    const elStatus = document.getElementById('sim-card-status');
    const elBrand = document.getElementById('sim-card-brand');

    if (elCarrier) elCarrier.textContent = currentSIM.carrier;
    if (elPhone) elPhone.textContent = currentSIM.phoneNumber;
    if (elIccid) elIccid.textContent = currentSIM.iccid;
    if (elImsi) elImsi.textContent = currentSIM.imsi;
    if (elEnclave) elEnclave.textContent = 'KNOX-SEC-ENCLAVE-994A-FF02';
    if (elBrand) elBrand.textContent = currentSIM.slotType.includes('eSIM') ? 'eSIM DIGITAL CHIP' : '5G SECURE CHIP';

    if (elStatus) {
      if (status === 'REGISTERED_SECURE') {
        elStatus.className = 'sim-status-badge verified';
        elStatus.textContent = 'ARMORED & REGISTERED';
      } else if (status === 'SIM_SWAP_ATTACK') {
        elStatus.className = 'sim-status-badge critical';
        elStatus.textContent = '🚨 UNRECOGNIZED SWAP THREAT';
      } else {
        elStatus.className = 'sim-status-badge unverified';
        elStatus.textContent = 'PENDING REGISTRATION';
      }
    }
  }

  // 3. Update Registered Profile Card
  const bindingDetails = document.getElementById('sim-binding-details');
  if (bindingDetails) {
    if (boundProfile) {
      document.getElementById('sim-cert-serial').textContent = boundProfile.certSerial;
      document.getElementById('sim-bound-owner').textContent = boundProfile.ownerName;
      document.getElementById('sim-bound-email').textContent = boundProfile.ownerEmail;
      document.getElementById('sim-bound-token').textContent = boundProfile.securityToken;
      document.getElementById('sim-bound-swap-status').textContent = boundProfile.antiSimSwapEnabled ? 'ACTIVE (LOCKDOWN ON MISMATCH)' : 'DISABLED';
      bindingDetails.style.display = 'block';
    } else {
      bindingDetails.style.display = 'none';
    }
  }

  // 4. Update Diagnostics & Threat Gauge
  updateThreatGauge(res.threatScore, res.threatLevel);
  populateFindings(res.indicators || res.details);

  if (status === 'SIM_SWAP_ATTACK') {
    if (_threatVerdictSummary) _threatVerdictSummary.textContent = 'CRITICAL TELECOM ALARM: Unauthorized SIM swap detected! IMSI/ICCID mismatch with Knox secure enclave.';
  } else if (status === 'REGISTERED_SECURE') {
    if (_threatVerdictSummary) _threatVerdictSummary.textContent = `SIM & Baseband Verified. Device cryptographically registered to ${boundProfile.ownerName}. Anti-SIM-Swap Active.`;
  } else if (status === 'UNREGISTERED') {
    if (_threatVerdictSummary) _threatVerdictSummary.textContent = 'Active SIM detected in pre-installed OEM device. Complete registration wizard to activate Anti-SIM-Swap defense.';
  } else {
    if (_threatVerdictSummary) _threatVerdictSummary.textContent = 'No active SIM detected in cellular socket.';
  }

  if (logToTerminal && res.logs) {
    res.logs.forEach(log => {
      let type = 'system';
      if (log.includes('[CRITICAL]')) type = 'critical';
      else if (log.includes('[WARN]') || log.includes('[PROMPT]')) type = 'warn';
      else if (log.includes('[SUCCESS]')) type = 'success';
      addLogLine(log, type);
    });
  }
}

function loadSIMScenario(scenarioKey) {
  if (!window.simRegistryEngine || !window.SIM_PRESETS[scenarioKey]) return;
  activeSIMPreset = scenarioKey;

  // Highlight active preset button
  const presetButtons = ['verizon', 'att', 'jio', 'rogue'];
  presetButtons.forEach(btnKey => {
    const btn = document.getElementById(`sim-btn-${btnKey}`);
    if (btn) {
      btn.classList.toggle('active', (btnKey === 'verizon' && scenarioKey === 'verizon_5g') ||
                                    (btnKey === 'att' && scenarioKey === 'att_fiber_sim') ||
                                    (btnKey === 'jio' && scenarioKey === 'jio_airtel_5g') ||
                                    (btnKey === 'rogue' && scenarioKey === 'rogue_swapped_sim'));
    }
  });

  initAudioContext();
  clearTerminal();

  addLogLine(`[TELECOM_HW] Cellular SIM event triggered: ${scenarioKey.toUpperCase()}`, 'system');
  const evaluation = window.simRegistryEngine.insertOrActivateSIM(window.SIM_PRESETS[scenarioKey]);
  applySIMEvaluation(evaluation, true);

  if (evaluation.status === 'SIM_SWAP_ATTACK') {
    playSirenAlarm();
  } else {
    stopSirenAlarm();
    playTone(587.33, 0.15, 0.05); // High D5 chime
  }
}

function runSIMSecurityAudit() {
  if (!window.simRegistryEngine) return;
  initAudioContext();
  clearTerminal();

  const auditBtn = document.getElementById('btn-run-sim-audit');
  if (auditBtn) auditBtn.setAttribute('disabled', 'true');

  addLogLine('[SYSTEM] Initiating deep telecom baseband & SIM cryptographic audit...', 'system');
  addLogLine('[SYSTEM] Querying 3GPP authentication vectors & Knox enclave status...', 'system');

  setTimeout(() => {
    const evalResult = window.simRegistryEngine.evaluateSIMSecurity();
    applySIMEvaluation(evalResult, true);
    
    // History Save
    if (window.historyManager && window.historyStore) {
      const targetDisplay = evalResult.currentSIM ? evalResult.currentSIM.iccid : 'NO_SIM';
      let verdict = 'SIM check complete';
      if (_threatVerdictSummary) verdict = _threatVerdictSummary.textContent;
      
      historyManager.createScanRecord('SIM_SHIELD', targetDisplay, {
        score: evalResult.threatScore,
        severity: evalResult.threatLevel,
        verdict: verdict,
        indicators: evalResult.indicators || evalResult.details || []
      }).then(record => historyStore.saveScan(record))
        .then(() => addLogLine(`[SYSTEM] Scan saved to history.`, 'success'))
        .catch(e => addLogLine(`[WARN] Could not save history: ${e.message}`, 'warn'));
    }

    if (auditBtn) auditBtn.removeAttribute('disabled');
    addLogLine(`[SUCCESS] Baseband audit complete. Threat Score: ${evalResult.threatScore}%`, evalResult.threatScore > 50 ? 'critical' : 'success');
  }, 700);
}

// SIM Registration Modal & Wizard Controls
function openSIMRegistrationModal() {
  initAudioContext();
  const modal = document.getElementById('sim-registration-modal');
  if (!modal) return;

  const currentSIM = window.simRegistryEngine ? window.simRegistryEngine.currentSIM : null;
  if (currentSIM) {
    document.getElementById('wiz-carrier').textContent = currentSIM.carrier;
    document.getElementById('wiz-phone').textContent = currentSIM.phoneNumber;
    document.getElementById('wiz-iccid').textContent = currentSIM.iccid;
    document.getElementById('wiz-imsi').textContent = currentSIM.imsi;
  }

  wizardNextStep(1);
  modal.classList.add('active');
  addLogLine('[PROMPT] Opened OEM Pre-Installed SIM Registration Wizard.', 'system');
}

function closeSIMRegistrationModal() {
  const modal = document.getElementById('sim-registration-modal');
  if (modal) modal.classList.remove('active');
}

function wizardNextStep(targetStep) {
  currentWizardStep = targetStep;

  // Toggle panes
  for (let i = 1; i <= 4; i++) {
    const pane = document.getElementById(`wizard-pane-${i}`);
    const node = document.getElementById(`wizard-step-node-${i}`);
    const line = document.getElementById(`wizard-line-${i}`);

    if (pane) pane.classList.toggle('active', i === targetStep);
    if (node) {
      node.classList.toggle('active', i === targetStep);
      node.classList.toggle('completed', i < targetStep);
    }
    if (line) {
      line.classList.toggle('active', i < targetStep);
    }
  }

  playTone(440 + targetStep * 50, 0.08, 0.03);
}

async function submitSIMRegistration() {
  if (!window.simRegistryEngine) return;

  const ownerName = document.getElementById('reg-owner-name').value.trim() || 'Authorized Device Owner';
  const ownerEmail = document.getElementById('reg-owner-email').value.trim() || 'alerts@trustandverify.com';
  const emergencyPhone = document.getElementById('reg-emergency-phone').value.trim() || '+1 (555) 911-0000';
  const deviceAssetTag = document.getElementById('reg-asset-tag').value.trim() || 'OEM-DEFENSE-DEVICE';
  const securityPin = document.getElementById('reg-security-pin').value.trim() || '1234';
  const antiSimSwapEnabled = document.getElementById('reg-policy-antiswap').checked;
  const autoCallScreening = document.getElementById('reg-policy-callscreen').checked;
  const roamingLockEnabled = document.getElementById('reg-policy-roaming').checked;

  try {
    const result = await window.simRegistryEngine.registerSIM({
      ownerName,
      ownerEmail,
      emergencyPhone,
      deviceAssetTag,
      securityPin,
      antiSimSwapEnabled,
      autoCallScreening,
      roamingLockEnabled
    });

    if (result.success) {
      const p = result.profile;
      document.getElementById('issued-cert-token').textContent = p.securityToken;
      document.getElementById('issued-cert-serial').textContent = p.certSerial;
      document.getElementById('issued-cert-owner').textContent = p.ownerName;
      document.getElementById('issued-cert-sim').textContent = `${p.simDetails.carrier} (${p.simDetails.imsi})`;

      wizardNextStep(4);
      playStartupChime();
      addLogLine(`[SUCCESS] Cryptographic SIM Binding complete! Token: ${p.securityToken}`, 'success');
    }
  } catch (err) {
    addLogLine(`[ERROR] SIM registration failed: ${err.message}`, 'critical');
  }
}

function finishSIMRegistration() {
  closeSIMRegistrationModal();
  initSIMState();
  addLogLine('[SYSTEM] Device status: ARMORED & REGISTERED. Real-time Anti-SIM-Swap daemon active.', 'success');
  playTone(880, 0.2, 0.05);
}

async function handleUnbindSIM() {
  if (!window.simRegistryEngine) return;
  // Use a dialog input; prompt() is a native blocking call.
  // Phase 1 UX task: replace with a custom modal dialog.
  const pin = prompt('Enter your 4-digit Master Knox PIN to unbind this SIM registration:');
  if (pin === null || pin.trim() === '') return; // User cancelled or entered nothing

  try {
    const result = await window.simRegistryEngine.unbindRegistration(pin.trim());
    if (result.success) {
      applySIMEvaluation(result.evaluation, true);
      addLogLine('[INFO] Device SIM registration unbound. Device returned to Unactivated Pre-Installed state.', 'warn');
      // Phase 1 UX task: replace alert() with a custom toast/modal notification.
      alert('SIM registration successfully cleared. Device is now in unverified pre-installed state.');
    } else {
      alert(result.error || 'Failed to unbind SIM.');
    }
  } catch (err) {
    addLogLine(`[ERROR] Unbind failed: ${err.message}`, 'critical');
    alert('An unexpected error occurred during SIM unbind.');
  }
}

// 10. Splash Screen Loader Sequence & App Init
document.addEventListener('DOMContentLoaded', () => {
  const splashScreen = document.getElementById('splash-screen');
  const splashProgress = document.getElementById('splash-progress');
  const splashBootLog = document.getElementById('splash-boot-log');

  const bootMessages = [
    { text: 'SYSTEM: STANDBY...', progress: 5 },
    { text: 'INITIALIZING SECURITY SUB-SYSTEMS...', progress: 18 },
    { text: 'SCANNING OEM BASEBAND & SIM HARDWARE...', progress: 32 },
    { text: 'LOADING THREAT-SIGNATURE DATABASE...', progress: 50 },
    { text: 'ESTABLISHING INTERCEPT HOOKS...', progress: 68 },
    { text: 'CONNECTING DNS SPF/DKIM ENDPOINTS...', progress: 84 },
    { text: 'VULNERABILITY CORE INTEGRITY: OK', progress: 95 },
    { text: 'TRUST & VERIFY DEPLOYED AND ONLINE.', progress: 100 }
  ];

  let currentMsgIdx = 0;

  function runBootSequence() {
    if (currentMsgIdx < bootMessages.length) {
      const step = bootMessages[currentMsgIdx];
      if (splashBootLog) splashBootLog.textContent = step.text;
      if (splashProgress) splashProgress.style.width = `${step.progress}%`;
      
      const delay = currentMsgIdx === bootMessages.length - 1 ? 500 : Math.random() * 200 + 120;
      
      currentMsgIdx++;
      setTimeout(runBootSequence, delay);
    } else {
      if (splashScreen) {
        splashScreen.classList.add('fade-out');
        setTimeout(() => {
          splashScreen.style.display = 'none';
        }, 800);
      }
      // Initialize SIM State on load
      initSIMState();
    }
  }

  // Start sequence
  setTimeout(runBootSequence, 200);
}

// ============================================================================
// PHASE 3: URL, QR, Domain & SSL Analyzers
// ============================================================================

function switchUrlQrTab(tabId) {
  document.getElementById('btn-tab-url').classList.toggle('active', tabId === 'url');
  document.getElementById('btn-tab-qr').classList.toggle('active', tabId === 'qr');
  document.getElementById('urlqr-tab-url').style.display = tabId === 'url' ? 'block' : 'none';
  document.getElementById('urlqr-tab-qr').style.display = tabId === 'qr' ? 'block' : 'none';
}

async function executeThreatIntel(target, type) {
  const container = document.getElementById('threat-intel-results');
  const grid = document.getElementById('ti-providers-grid');
  
  if (!container || !grid) return null;
  
  container.style.display = 'block';
  grid.innerHTML = '<div style="color: #aaa;">Checking external threat intelligence...</div>';
  addLogLine(`[INFO] Querying Threat Intelligence for ${type}: ${target}`, 'system');
  
  try {
    const res = await fetch(`/api/threat-intel/${type.toLowerCase()}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target })
    });
    
    if (!res.ok) {
      grid.innerHTML = `<div style="color: #ff5555;">Threat Intelligence unavailable (${res.status})</div>`;
      return null;
    }
    
    const data = await res.json();
    
    grid.innerHTML = '';
    const newIndicators = [];
    
    if (data.results && data.results.length > 0) {
      data.results.forEach(r => {
        let statusColor = '#aaa';
        if (r.status === 'FOUND') statusColor = '#ff5555';
        else if (r.status === 'NO_MATCH') statusColor = '#55ff55';
        
        let details = '';
        if (r.reputation) {
          details = `<br><span style="font-size:10px">Malicious: ${r.reputation.malicious}, Suspicious: ${r.reputation.suspicious}</span>`;
          if (r.reputation.malicious > 0 || r.reputation.suspicious > 0) {
            newIndicators.push({
              id: `TI_${r.provider.toUpperCase().replace(/\s/g, '_')}_MALICIOUS`,
              category: 'THREAT_INTELLIGENCE',
              severity: r.reputation.malicious > 0 ? 'HIGH' : 'MEDIUM',
              title: `${r.provider} Malicious Detection`,
              description: `Target was flagged by ${r.provider}.`,
              evidence: `Malicious: ${r.reputation.malicious}, Suspicious: ${r.reputation.suspicious}`,
              recommendation: 'Block this target immediately.'
            });
          }
        }
        if (r.detections) {
          details = `<br><span style="font-size:10px">${r.detections.length} threat matches</span>`;
          if (r.detections.length > 0) {
            newIndicators.push({
              id: `TI_${r.provider.toUpperCase().replace(/\s/g, '_')}_MATCH`,
              category: 'THREAT_INTELLIGENCE',
              severity: 'HIGH',
              title: `${r.provider} Threat Match`,
              description: `Target matched in ${r.provider} database.`,
              evidence: `${r.detections.length} matches found.`,
              recommendation: 'Block this target.'
            });
          }
        }
        if (r.metadata && r.metadata.in_database) {
            newIndicators.push({
              id: `TI_${r.provider.toUpperCase().replace(/\s/g, '_')}_MATCH`,
              category: 'THREAT_INTELLIGENCE',
              severity: 'HIGH',
              title: `${r.provider} Phishing Match`,
              description: `Target matched in ${r.provider} database.`,
              evidence: `Found in database.`,
              recommendation: 'Block this target.'
            });
        }
        
        grid.innerHTML += `
          <div class="eml-data-row">
            <span class="eml-data-label">${r.provider.toUpperCase()}</span>
            <span class="eml-data-value" style="color: ${statusColor};">${r.status}${details}</span>
          </div>
        `;
      });
    } else {
      grid.innerHTML = '<div style="color: #aaa;">No threat intelligence data available.</div>';
    }
    
    return newIndicators;
  } catch (err) {
    grid.innerHTML = `<div style="color: #ff5555;">Threat Intelligence request failed: ${err.message}</div>`;
    return null;
  }
}

async function runUrlScan() {
  const urlInput = document.getElementById('url-input').value;
  if (!urlInput.trim()) {
    addLogLine('[ERROR] Target URL is empty', 'error');
    return;
  }
  
  if (typeof UrlAnalyzer === 'undefined') {
    addLogLine('[ERROR] URL Analyzer module not loaded', 'error');
    return;
  }

  addLogLine(`[INFO] Analyzing URL: ${urlInput}`, 'system');
  const result = UrlAnalyzer.analyze(urlInput);
  
  // Format for Risk Engine
  const riskResult = RiskEngine.analyze({
    module: 'url',
    indicators: result.indicators,
    metadata: {
      normalizedUrl: result.normalizedUrl,
      nestedUrl: result.nestedUrl
    }
  });

  updateThreatGauge(riskResult.score, riskResult.severity, riskResult.verdict, riskResult.summary);
  renderRiskFindings(riskResult.indicators);

  document.getElementById('url-breakdown').style.display = 'block';
  document.getElementById('url-parts-grid').innerHTML = `
    <div class="eml-data-row"><span class="eml-data-label">PROTOCOL</span><span class="eml-data-value">${result.parsed?.protocol || '-'}</span></div>
    <div class="eml-data-row"><span class="eml-data-label">HOSTNAME</span><span class="eml-data-value">${result.parsed?.hostname || '-'}</span></div>
    <div class="eml-data-row"><span class="eml-data-label">PATH</span><span class="eml-data-value">${result.parsed?.pathname || '-'}</span></div>
    <div class="eml-data-row"><span class="eml-data-label">QUERY</span><span class="eml-data-value">${result.parsed?.search || '-'}</span></div>
  `;

  let scanId = null;
  if (window.historyManager && window.historyStore) {
    try {
      const record = await historyManager.createScanRecord('URL_SECURITY', urlInput, riskResult);
      scanId = await historyStore.saveScan(record);
      addLogLine(`[SYSTEM] Scan saved to history.`, 'success');
    } catch(e) {
      addLogLine(`[WARN] Could not save history: ${e.message}`, 'warn');
    }
  }

  // External Threat Intelligence
  const useTi = document.getElementById('url-ti-toggle')?.checked;
  if (useTi) {
    const tiIndicators = await executeThreatIntel(urlInput, 'URL');
    
    let finalResult = riskResult;
    
    if (tiIndicators && tiIndicators.length > 0) {
      const combinedIndicators = [...result.indicators, ...tiIndicators];
      finalResult = RiskEngine.analyze({
        module: 'url',
        indicators: combinedIndicators,
        metadata: { normalizedUrl: result.normalizedUrl, nestedUrl: result.nestedUrl }
      });
      updateThreatGauge(finalResult.score, finalResult.severity, finalResult.verdict, finalResult.summary);
      renderRiskFindings(finalResult.indicators);
    }
    
    if (scanId && window.historyStore && window.lastTiResult) {
      try {
        await historyStore.updateScan(scanId, { 
           result: finalResult, 
           threatIntelligence: window.lastTiResult 
        });
      } catch(e) {}
    }
  } else {
    document.getElementById('threat-intel-results').style.display = 'none';
  }
}

let selectedQrImage = null;
function handleQrSelect(event) {
  const file = event.target.files[0];
  if (!file) return;
  selectedQrImage = file;
  
  document.getElementById('qr-dropzone').style.display = 'none';
  document.getElementById('qr-info-card').style.display = 'flex';
  document.getElementById('selected-qr-name').innerText = file.name;
  document.getElementById('selected-qr-size').innerText = `${Math.round(file.size / 1024)} KB`;
  document.getElementById('btn-run-qr').disabled = false;
}

function clearSelectedQr() {
  selectedQrImage = null;
  document.getElementById('qr-input').value = '';
  document.getElementById('qr-dropzone').style.display = 'flex';
  document.getElementById('qr-info-card').style.display = 'none';
  document.getElementById('btn-run-qr').disabled = true;
  document.getElementById('qr-results').style.display = 'none';
}

function runQrScan() {
  if (!selectedQrImage) return;
  
  const reader = new FileReader();
  reader.onload = function(e) {
    const img = new Image();
    img.onload = function() {
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      
      try {
        const code = jsQR(imageData.data, imageData.width, imageData.height);
        if (code) {
          addLogLine(`[INFO] QR Code decoded. Payload: ${code.data}`, 'system');
          processQrPayload(code.data);
        } else {
          addLogLine('[ERROR] No QR code found in the image', 'error');
        }
      } catch (err) {
        addLogLine(`[ERROR] QR Decoding failed: ${err.message}`, 'error');
      }
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(selectedQrImage);
}

function processQrPayload(decodedText) {
  if (typeof QrAnalyzer === 'undefined') {
    addLogLine('[ERROR] QR Analyzer module not loaded', 'error');
    return;
  }
  
  const result = QrAnalyzer.analyze(decodedText);
  
  document.getElementById('qr-results').style.display = 'block';
  document.getElementById('qr-type-val').innerText = result.type;
  document.getElementById('qr-payload-val').innerText = result.rawText;

  let riskResult;
  if (result.type === 'URL' && typeof UrlAnalyzer !== 'undefined') {
    const urlResult = UrlAnalyzer.analyze(result.urlPayload);
    // Merge indicators
    const combinedIndicators = [...result.indicators, ...urlResult.indicators];
    riskResult = RiskEngine.analyze({
      module: 'qr',
      indicators: combinedIndicators
    });
  } else {
    riskResult = RiskEngine.analyze({
      module: 'qr',
      indicators: result.indicators
    });
  }

  updateThreatGauge(riskResult.score, riskResult.severity, riskResult.verdict, riskResult.summary);
  renderRiskFindings(riskResult.indicators);
}

function runDomainScan() {
  runDomainScanAsync().catch(err => console.error(err));
}

async function runDomainScanAsync() {
  const domainInput = document.getElementById('domain-input').value.trim();
  if (!domainInput) {
    addLogLine('[ERROR] Target Domain is empty', 'error');
    return;
  }
  
  if (typeof DomainAnalyzer === 'undefined') {
    addLogLine('[ERROR] Domain Analyzer module not loaded', 'error');
    return;
  }

  addLogLine(`[INFO] Analyzing Domain: ${domainInput}`, 'system');
  const result = DomainAnalyzer.analyze(domainInput);
  
  let riskResult = RiskEngine.analyze({
    module: 'domain',
    indicators: result.indicators,
    metadata: {
      registrableDomain: result.registrableDomain
    }
  });

  updateThreatGauge(riskResult.score, riskResult.severity, riskResult.verdict, riskResult.summary);
  renderRiskFindings(riskResult.indicators);

  let scanId = null;
  if (window.historyManager && window.historyStore) {
    try {
      const record = await historyManager.createScanRecord('DOMAIN_INSPECTOR', domainInput, riskResult);
      scanId = await historyStore.saveScan(record);
      addLogLine(`[SYSTEM] Scan saved to history.`, 'success');
    } catch(e) {
      addLogLine(`[WARN] Could not save history: ${e.message}`, 'warn');
    }
  }

  // External Threat Intelligence
  const useTi = document.getElementById('domain-ti-toggle')?.checked;
  if (useTi) {
    const tiIndicators = await executeThreatIntel(domainInput, 'DOMAIN');
    let finalResult = riskResult;
    
    if (tiIndicators && tiIndicators.length > 0) {
      const combinedIndicators = [...result.indicators, ...tiIndicators];
      finalResult = RiskEngine.analyze({
        module: 'domain',
        indicators: combinedIndicators,
        metadata: { registrableDomain: result.registrableDomain }
      });
      updateThreatGauge(finalResult.score, finalResult.severity, finalResult.verdict, finalResult.summary);
      renderRiskFindings(finalResult.indicators);
    }
    
    if (scanId && window.historyStore && window.lastTiResult) {
      try {
        await historyStore.updateScan(scanId, { 
           result: finalResult, 
           threatIntelligence: window.lastTiResult 
        });
      } catch(e) {}
    }
  } else {
    document.getElementById('threat-intel-results').style.display = 'none';
  }
}

async function runSslScan() {
  const domainInput = document.getElementById('domain-input').value.trim();
  if (!domainInput) {
    addLogLine('[ERROR] Target Domain is empty', 'error');
    return;
  }
  
  if (typeof SslAnalyzer === 'undefined') {
    addLogLine('[ERROR] SSL Analyzer module not loaded', 'error');
    return;
  }

  addLogLine(`[INFO] Requesting TLS inspection for: ${domainInput}`, 'system');
  
  // Set UI state to scanning
  document.getElementById('ssl-results').style.display = 'block';
  document.getElementById('ssl-details-grid').innerHTML = 'Inspecting... Please wait up to 5s.';

  try {
    const result = await SslAnalyzer.inspect(domainInput);
    const riskResult = RiskEngine.analyze({
      module: 'ssl',
      indicators: result.indicators
    });

    updateThreatGauge(riskResult.score, riskResult.severity, riskResult.verdict, riskResult.summary);
    renderRiskFindings(riskResult.indicators);

    if (result.sslData) {
      document.getElementById('ssl-details-grid').innerHTML = `
        <div class="eml-data-row"><span class="eml-data-label">ISSUER</span><span class="eml-data-value">${result.sslData.certificate?.issuer?.CN || '-'}</span></div>
        <div class="eml-data-row"><span class="eml-data-label">SUBJECT</span><span class="eml-data-value">${result.sslData.certificate?.subject?.CN || '-'}</span></div>
        <div class="eml-data-row"><span class="eml-data-label">PROTOCOL</span><span class="eml-data-value">${result.sslData.protocol || '-'}</span></div>
        <div class="eml-data-row"><span class="eml-data-label">EXPIRES IN</span><span class="eml-data-value">${Math.floor(result.sslData.daysUntilExpiry)} days</span></div>
      `;
    } else {
      document.getElementById('ssl-details-grid').innerHTML = 'Failed to retrieve SSL details.';
    }

    if (window.historyManager && window.historyStore) {
      try {
        const record = await historyManager.createScanRecord('SSL_INSPECTOR', domainInput, riskResult);
        await historyStore.saveScan(record);
        addLogLine(`[SYSTEM] Scan saved to history.`, 'success');
      } catch(e) {
        addLogLine(`[WARN] Could not save history: ${e.message}`, 'warn');
      }
    }
  } catch (err) {
    addLogLine(`[ERROR] SSL Scan failed: ${err.message}`, 'error');
    document.getElementById('ssl-details-grid').innerHTML = err.message;
  }
}
