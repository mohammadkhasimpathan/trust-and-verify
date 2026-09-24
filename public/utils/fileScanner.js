/**
 * fileScanner.js
 * Performs heuristic analysis on file attachments for malware/ransomware signatures.
 */

var _re = (typeof require === 'function' && typeof window === 'undefined') 
  ? require('../core/riskEngine') 
  : (typeof window !== 'undefined' ? window.RiskEngine : null);

// Simulated database of dangerous file hashes (SHA-256)
const THREAT_HASHES = {
  // WannaCry ransomware
  '24d00b4295d0393987f250fa0f5af9d95f903fb4e9e19d71d64b66dfab0fcf0c': {
    name: 'WannaCry Ransomware',
    type: 'Ransomware',
    severity: 'Critical',
    description: 'A notorious self-replicating ransomware cryptoworm that targets Windows computers, encrypting data and demanding Bitcoin ransom payments.'
  },
  // LockBit ransomware
  'f7f7394cfbf362bb56372c05f778db10642fa6ff9be83be2e3074092d62d22a5': {
    name: 'LockBit Ransomware',
    type: 'Ransomware',
    severity: 'Critical',
    description: 'Active ransomware-as-a-service (RaaS) family that automates encryption, targets corporate networks, and utilizes double-extortion tactics.'
  },
  // Ryuk ransomware
  'bca3d3876eb5c179c323f668af80998f4803b9b478d103328e3b5df54b5f9001': {
    name: 'Ryuk Ransomware',
    type: 'Ransomware',
    severity: 'Critical',
    description: 'Highly targeted ransomware typically deployed via phishing/Trojan attacks. Focuses on high-value systems, encrypting critical assets.'
  },
  // TrickBot Trojan (often drops ransomware)
  'e6475fde39a16f9f6e6cd4e207a9e6fb22cb820ebad88a9134a6ef4e0cfef960': {
    name: 'TrickBot Banker Trojan',
    type: 'Trojan/Downloader',
    severity: 'High',
    description: 'Sophisticated malware used to harvest credentials, propagate laterally, and deploy ransomware families such as Conti or Ryuk.'
  }
};

function analyzeFile(filename, contentBufferOrString, fileHash = '') {
  const reports = [];
  let score = 0;
  const details = [];
  const indicators = [];

  if (!filename) {
    return {
      threatLevel: 'Unknown',
      score: 0,
      logs: ['[ERROR] No filename provided for scanning.'],
      details: [],
      indicators: []
    };
  }

  reports.push(`[INFO] Starting heuristic scan for file: ${filename}`);

  // 1. Analyze File Extension
  const extensionMatch = filename.match(/\.([^.]+)$/);
  const ext = extensionMatch ? extensionMatch[1].toLowerCase() : '';

  reports.push(`[INFO] Detected extension: .${ext || 'none'}`);

  // High-risk extensions (executable/script files commonly used to deliver ransomware payloads)
  const executableExtensions = ['exe', 'scr', 'bat', 'com', 'cmd', 'msi', 'inf'];
  const scriptExtensions = ['js', 'vbs', 'vbe', 'wsf', 'ps1', 'sh', 'lnk', 'hta', 'pif', 'jar', 'reg'];
  const macroExtensions = ['docm', 'xlsm', 'pptm', 'doc', 'xls', 'ppt']; // Office files with macros enabled or legacy formats

  if (executableExtensions.includes(ext)) {
    score += 85;
    reports.push(`[CRITICAL] File is a binary executable (ext: .${ext}). Executable attachments are highly restricted.`);
    details.push({
      type: 'danger',
      title: 'Dangerous Executable Extension',
      message: `The file ends in a dangerous executable extension (.${ext}). Malware and ransomware are frequently compiled into executable files that launch automatically when opened.`
    });
    indicators.push({
      id: 'FILE_EXTENSION_EXECUTABLE',
      category: 'ATTACHMENT',
      severity: 'CRITICAL',
      weight: 85,
      title: 'Dangerous Executable Extension',
      description: `The file ends in a dangerous executable extension (.${ext}). Malware and ransomware are frequently compiled into executable files.`,
      evidence: `Extension: .${ext}`,
      recommendation: 'Do not run this file. Delete it immediately.',
      source: 'LOCAL_HEURISTIC'
    });
  } else if (scriptExtensions.includes(ext)) {
    score += 75;
    reports.push(`[CRITICAL] File is a script file (ext: .${ext}). Scripts can run system commands and download payloads.`);
    details.push({
      type: 'danger',
      title: 'Script-based Threat Vector',
      message: `Script files (.${ext}) can run administrative shell commands on your operating system, bypassing security controls to download and install ransomware in the background.`
    });
    indicators.push({
      id: 'FILE_EXTENSION_SCRIPT',
      category: 'ATTACHMENT',
      severity: 'CRITICAL',
      weight: 75,
      title: 'Script-based Threat Vector',
      description: `Script files (.${ext}) can run administrative shell commands on your operating system.`,
      evidence: `Extension: .${ext}`,
      recommendation: 'Do not execute script files from unknown sources.',
      source: 'LOCAL_HEURISTIC'
    });
  } else if (macroExtensions.includes(ext)) {
    score += 40;
    reports.push(`[WARN] File format supports macros (ext: .${ext}). Macros can contain malicious VBA code.`);
    details.push({
      type: 'warning',
      title: 'Macro-Enabled Document Alert',
      message: `Office documents (.${ext}) can contain embedded VBA macros. Attackers use social engineering to trick victims into enabling macros, which then triggers a malware download.`
    });
    indicators.push({
      id: 'FILE_EXTENSION_MACRO',
      category: 'ATTACHMENT',
      severity: 'MEDIUM',
      weight: 40,
      title: 'Macro-Enabled Document Alert',
      description: `Office documents (.${ext}) can contain embedded VBA macros.`,
      evidence: `Extension: .${ext}`,
      recommendation: 'Do not enable macros or editing if prompted by the document reader.',
      source: 'LOCAL_HEURISTIC'
    });
  } else if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) {
    score += 25;
    reports.push(`[WARN] File is a compressed archive (ext: .${ext}). Archives are frequently used to hide executable malware from basic scanners.`);
    details.push({
      type: 'warning',
      title: 'Archive Encryption / Obfuscation Risk',
      message: `Compressed archive files (.${ext}) are often used to wrap malicious payloads. Attackers zip files to bypass basic network scanners and email gateway filters.`
    });
    indicators.push({
      id: 'FILE_EXTENSION_ARCHIVE',
      category: 'ATTACHMENT',
      severity: 'LOW',
      weight: 25,
      title: 'Archive Encryption / Obfuscation Risk',
      description: `Compressed archive files (.${ext}) are often used to wrap malicious payloads.`,
      evidence: `Extension: .${ext}`,
      recommendation: 'Exercise caution when extracting files. Scan the extracted contents before opening.',
      source: 'LOCAL_HEURISTIC'
    });
  } else {
    reports.push(`[OK] Extension format .${ext || 'plain'} is classified as low risk for direct execution.`);
  }

  // 2. Hash Reputation Check
  if (fileHash) {
    const cleanHash = fileHash.toLowerCase().trim();
    reports.push(`[INFO] SHA-256 Hash computed: ${cleanHash}`);
    if (THREAT_HASHES[cleanHash]) {
      const threat = THREAT_HASHES[cleanHash];
      score = Math.max(score, 100); // 100% Threat
      reports.push(`[CRITICAL] HASH MATCH DETECTED! Threat identified: ${threat.name} (${threat.type})`);
      details.push({
        type: 'danger',
        title: `Signature Match: ${threat.name}`,
        message: `This file's cryptographic hash aligns exactly with a known sample of ${threat.name} (${threat.type}). ${threat.description} Immediate quarantine required.`
      });
      indicators.push({
        id: `FILE_HASH_MATCH_${cleanHash.substring(0, 8)}`,
        category: 'REPUTATION',
        severity: 'CRITICAL',
        weight: 100,
        title: `Signature Match: ${threat.name}`,
        description: `This file's cryptographic hash aligns exactly with a known sample of ${threat.name} (${threat.type}). ${threat.description}`,
        evidence: `SHA256: ${cleanHash}`,
        recommendation: 'Immediate quarantine required. Do not execute this file.',
        source: 'LOCAL_HEURISTIC'
      });
    } else {
      reports.push(`[OK] Hash does not match any known signatures in local malware threat database.`);
    }
  }

  // 3. Heuristic Code Content Scan (if content is readable as text/code)
  if (contentBufferOrString) {
    let contentString = '';
    if (typeof contentBufferOrString === 'string') {
      contentString = contentBufferOrString;
    } else if (typeof Buffer !== 'undefined' && Buffer.isBuffer(contentBufferOrString)) {
      contentString = contentBufferOrString.toString('utf8');
    }

    if (contentString) {
      // Look for suspicious keywords often found in email scripts/downloader malware
      const rules = [
        { regex: /WScript\.Shell/i, score: 30, desc: 'Windows Script Host instantiation (WScript.Shell)' },
        { regex: /ActiveXObject/i, score: 30, desc: 'ActiveX object creation (ActiveXObject)' },
        { regex: /ShellExecute/i, score: 35, desc: 'Shell command execution API (ShellExecute)' },
        { regex: /powershell/i, score: 20, desc: 'PowerShell process activation' },
        { regex: /AutoOpen|Document_Open/i, score: 25, desc: 'Automatic macro trigger function (AutoOpen/Document_Open)' },
        { regex: /eval\s*\(/i, score: 15, desc: 'Dynamic code execution (eval)' },
        { regex: /Net\.WebClient|downloadfile/i, score: 30, desc: 'Web payload downloader methods (WebClient/DownloadFile)' },
        { regex: /cmd\.exe\s+\/c/i, score: 25, desc: 'System shell bypass trigger (cmd.exe /c)' }
      ];

      let foundCount = 0;
      for (const ind of rules) {
        if (ind.regex.test(contentString)) {
          score += ind.score;
          foundCount++;
          reports.push(`[CRITICAL] Content scan triggered: Detected ${ind.desc}`);
          details.push({
            type: 'danger',
            title: `Suspicious Script Pattern: ${ind.desc}`,
            message: `The file contents contain code matching a pattern highly correlated with automated downloaders and macros: "${ind.regex}".`
          });
          indicators.push({
            id: `FILE_SCRIPT_PATTERN_${ind.desc.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}`,
            category: 'CONTENT',
            severity: 'HIGH',
            weight: ind.score,
            title: `Suspicious Script Pattern: ${ind.desc}`,
            description: `The file contents contain code matching a pattern highly correlated with automated downloaders and macros: "${ind.regex}".`,
            evidence: ind.desc,
            recommendation: 'Do not run this file. Delete it immediately.',
            source: 'LOCAL_HEURISTIC'
          });
        }
      }

      if (foundCount === 0) {
        reports.push(`[OK] Content heuristic analysis found no obvious malicious scripting commands.`);
      }
    }
  }

  let finalRiskResult = null;
  if (_re) {
    finalRiskResult = _re.analyze({
      module: 'file',
      indicators,
      metadata: { filename, hash: fileHash }
    });
  }

  // Determine threat level based on score (legacy)
  let threatLevel = 'Safe';
  if (score >= 75) {
    threatLevel = 'Critical';
  } else if (score >= 50) {
    threatLevel = 'High';
  } else if (score >= 25) {
    threatLevel = 'Medium';
  } else if (score > 0) {
    threatLevel = 'Low';
  }

  return {
    threatLevel: finalRiskResult ? (finalRiskResult.severity.charAt(0) + finalRiskResult.severity.slice(1).toLowerCase()) : threatLevel,
    score: finalRiskResult ? finalRiskResult.score : Math.min(score, 100),
    logs: reports,
    details: finalRiskResult ? finalRiskResult.indicators.map(i => ({
      type: (i.severity === 'HIGH' || i.severity === 'CRITICAL') ? 'danger' : 'warning',
      title: i.title,
      message: i.description
    })) : details,
    indicators: finalRiskResult ? finalRiskResult.indicators : indicators,
    verdict: finalRiskResult ? finalRiskResult.verdict : 'UNKNOWN',
    summary: finalRiskResult ? finalRiskResult.summary : ''
  };
}

// Support both CommonJS node environment and global browser export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyzeFile, THREAT_HASHES };
} else {
  window.analyzeFile = analyzeFile;
  window.THREAT_HASHES = THREAT_HASHES;
}
