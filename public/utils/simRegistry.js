/**
 * simRegistry.js
 * Core Telecom & SIM Security Registry Engine for Trust & Verify.
 * Manages OEM Pre-Installed device states, SIM insertion/activation events,
 * cryptographic SIM binding, anti-SIM swap attack detection, and telecom telemetry.
 *
 * SECURITY DISCLAIMER:
 * This module is a CLIENT-SIDE SIMULATION for cybersecurity education purposes.
 * It uses browser localStorage, which is NOT a secure hardware enclave.
 * This code does NOT have real Knox/StrongBox access, does NOT interact with
 * actual SIM hardware, and does NOT provide real telecom security guarantees.
 * All threat verdicts and security status indicators are simulated heuristics.
 */

const STORAGE_KEY_SIM_REGISTRATION = 'trust_verify_sim_reg';
const STORAGE_KEY_OEM_CONFIG = 'trust_verify_oem_config';
const STORAGE_KEY_PIN_HASH = 'trust_verify_pin_hash';

// Default mock hardware specs
const DEFAULT_HARDWARE_IMEI = '358924091823901';
const DEFAULT_HARDWARE_ENCLAVE_ID = 'KNOX-SEC-ENCLAVE-994A-FF02';

let RiskEngine;
if (typeof require === 'function') {
  try {
    RiskEngine = require('../core/riskEngine');
  } catch (e) {
    RiskEngine = typeof window !== 'undefined' ? window.RiskEngine : null;
  }
} else {
  RiskEngine = typeof window !== 'undefined' ? window.RiskEngine : null;
}

// Simulated preset SIM cards
const SIM_PRESETS = {
  verizon_5g: {
    id: 'sim_verizon',
    phoneNumber: '+1 (555) 234-8901',
    carrier: 'Verizon 5G Ultra Wideband',
    countryCode: 'US (+1)',
    imsi: '311480123456789',
    iccid: '89014103211118552091',
    slotType: 'Physical Nano-SIM (Slot 1)',
    networkType: '5G SA (Standalone / Encrypted)',
    roaming: false,
    signalStrength: '94% (-68 dBm)',
    carrierTrustScore: 98,
    isSuspicious: false
  },
  att_fiber_sim: {
    id: 'sim_att',
    phoneNumber: '+1 (555) 883-4920',
    carrier: 'AT&T Mobility 5G+',
    countryCode: 'US (+1)',
    imsi: '310410987654321',
    iccid: '89011703248810293842',
    slotType: 'eSIM Embedded Profile 1',
    networkType: '5G NSA (Sub-6 GHz)',
    roaming: false,
    signalStrength: '88% (-74 dBm)',
    carrierTrustScore: 95,
    isSuspicious: false
  },
  jio_airtel_5g: {
    id: 'sim_jio',
    phoneNumber: '+91 98230 45671',
    carrier: 'Jio True 5G Prime',
    countryCode: 'IN (+91)',
    imsi: '405854001928374',
    iccid: '89918540192837482910',
    slotType: 'Physical Nano-SIM (Slot 1)',
    networkType: '5G SA VoNR',
    roaming: false,
    signalStrength: '96% (-65 dBm)',
    carrierTrustScore: 96,
    isSuspicious: false
  },
  rogue_swapped_sim: {
    id: 'sim_swapped_attack',
    phoneNumber: '+1 (555) 019-9988',
    carrier: 'Untrusted Virtual MVNO Relay',
    countryCode: 'Unknown / Spoofed',
    imsi: '999888777666555',
    iccid: '89000000000000000000',
    slotType: 'Cloned Physical SIM (Slot 1)',
    networkType: '2G/3G GSM Legacy Fallback (Unencrypted)',
    roaming: true,
    signalStrength: '42% (-108 dBm)',
    carrierTrustScore: 12,
    isSuspicious: true,
    attackDetails: 'Unregistered foreign IMSI detected. Cryptographic Knox handshake signature mismatch. Possible SIM-Swap / IMSI-Catcher MitM intercept in progress!'
  }
};

/**
 * SIM Registry Controller
 */
class SIMRegistryEngine {
  constructor() {
    this.isOEMPreInstalled = true;
    this.currentSIM = null;
    this.boundProfile = null;
    this.init();
  }

  init() {
    // Load persisted OEM config
    const savedConfig = localStorage.getItem(STORAGE_KEY_OEM_CONFIG);
    if (savedConfig) {
      try {
        const parsed = JSON.parse(savedConfig);
        this.isOEMPreInstalled = parsed.isOEMPreInstalled ?? true;
      } catch (e) {
        console.error('Failed to parse OEM config', e);
      }
    }

    // Load registered profile from localStorage
    const savedReg = localStorage.getItem(STORAGE_KEY_SIM_REGISTRATION);
    if (savedReg) {
      try {
        this.boundProfile = JSON.parse(savedReg);
      } catch (e) {
        console.error('Failed to parse saved SIM registration', e);
      }
    }

    // Default current active SIM if none set
    if (!this.currentSIM) {
      if (this.boundProfile && this.boundProfile.simDetails) {
        this.currentSIM = { ...this.boundProfile.simDetails };
      } else {
        // Default to a fresh unactivated Verizon SIM ready for registration
        this.currentSIM = { ...SIM_PRESETS.verizon_5g };
      }
    }
  }

  setOEMMode(isOEM) {
    this.isOEMPreInstalled = isOEM;
    localStorage.setItem(STORAGE_KEY_OEM_CONFIG, JSON.stringify({ isOEMPreInstalled: isOEM }));
  }

  insertOrActivateSIM(simData) {
    this.currentSIM = { ...simData };
    return this.evaluateSIMSecurity();
  }

  removeSIM() {
    this.currentSIM = null;
    return this.evaluateSIMSecurity();
  }

  /**
   * Evaluates the current SIM against the registered device security profile
   */
  evaluateSIMSecurity() {
    const logs = [];
    const details = [];
    const indicators = [];
    let threatScore = 0;
    let status = 'UNREGISTERED'; // 'NO_SIM', 'UNREGISTERED', 'REGISTERED_SECURE', 'SIM_SWAP_ATTACK'

    logs.push('[TELECOM_DAEMON] Scanning cellular baseband & hardware SIM socket...');

    if (!this.currentSIM) {
      status = 'NO_SIM';
      logs.push('[WARN] SIM Socket 1 is EMPTY. Cellular radio offline.');
      
      let finalRiskResult = null;
      if (RiskEngine) {
        indicators.push({
          id: 'SIM_NO_CARD',
          category: 'ATTACHMENT', // Reusing ATTACHMENT conceptually or HARDWARE
          severity: 'INFO',
          weight: 0,
          title: 'No SIM Card Detected',
          description: 'Device has no active SIM card inserted.',
          evidence: 'SIM socket empty.',
          recommendation: 'Insert a SIM card to activate network connection.',
          source: 'LOCAL_HEURISTIC'
        });
        finalRiskResult = RiskEngine.analyze({
          module: 'sim',
          indicators,
          metadata: { hasSim: false }
        });
      }

      return {
        status,
        threatScore: finalRiskResult ? finalRiskResult.score : 0,
        threatLevel: finalRiskResult ? (finalRiskResult.severity.charAt(0) + finalRiskResult.severity.slice(1).toLowerCase()) : 'Low',
        logs,
        details: finalRiskResult ? finalRiskResult.indicators.map(i => ({
          type: (i.severity === 'HIGH' || i.severity === 'CRITICAL') ? 'danger' : 'warning',
          title: i.title,
          message: i.description
        })) : [{
          type: 'warning',
          title: 'No SIM Card Detected',
          message: 'Device has no active SIM card inserted. Insert and activate a SIM card to configure cellular cyber protection.'
        }],
        indicators: finalRiskResult ? finalRiskResult.indicators : indicators,
        verdict: finalRiskResult ? finalRiskResult.verdict : 'UNKNOWN',
        summary: finalRiskResult ? finalRiskResult.summary : '',
        currentSIM: null,
        boundProfile: this.boundProfile
      };
    }

    logs.push(`[INFO] Carrier Detected: ${this.currentSIM.carrier}`);
    logs.push(`[INFO] Phone Number: ${this.currentSIM.phoneNumber}`);
    logs.push(`[INFO] ICCID Chip ID: ${this.currentSIM.iccid}`);
    logs.push(`[INFO] IMSI Telemetry: ${this.currentSIM.imsi}`);
    logs.push(`[INFO] Network Bearer: ${this.currentSIM.networkType}`);

    // If no SIM is registered yet
    if (!this.boundProfile) {
      status = 'UNREGISTERED';
      threatScore = 15;
      logs.push('[WARN] SIM is active but NOT cryptographically registered with Trust & Verify.');
      logs.push('[PROMPT] OEM Pre-installed registration wizard required.');
      details.push({
        type: 'warning',
        title: 'SIM Activation & Device Registration Pending',
        message: 'A SIM card has been activated in this pre-installed device. Complete the registration wizard to bind your cryptographic hardware key and enable Anti-SIM Swap defense.'
      });
      indicators.push({
        id: 'SIM_UNREGISTERED',
        category: 'IDENTITY',
        severity: 'LOW',
        weight: 15,
        title: 'SIM Activation & Device Registration Pending',
        description: 'A SIM card has been activated in this pre-installed device but is not registered.',
        evidence: 'No bound cryptographic profile found.',
        recommendation: 'Complete the registration wizard to bind your cryptographic hardware key.',
        source: 'LOCAL_HEURISTIC'
      });

      let finalRiskResult = null;
      if (RiskEngine) {
        finalRiskResult = RiskEngine.analyze({
          module: 'sim',
          indicators,
          metadata: { hasSim: true, registered: false }
        });
      }

      return {
        status,
        threatScore: finalRiskResult ? finalRiskResult.score : threatScore,
        threatLevel: finalRiskResult ? (finalRiskResult.severity.charAt(0) + finalRiskResult.severity.slice(1).toLowerCase()) : 'Low',
        logs,
        details: finalRiskResult ? finalRiskResult.indicators.map(i => ({
          type: (i.severity === 'HIGH' || i.severity === 'CRITICAL') ? 'danger' : 'warning',
          title: i.title,
          message: i.description
        })) : details,
        indicators: finalRiskResult ? finalRiskResult.indicators : indicators,
        verdict: finalRiskResult ? finalRiskResult.verdict : 'UNKNOWN',
        summary: finalRiskResult ? finalRiskResult.summary : '',
        currentSIM: this.currentSIM,
        boundProfile: null
      };
    }

    // A registration exists! Verify if the current SIM matches the bound cryptographic registration
    const boundSIM = this.boundProfile.simDetails;
    const isMatchingIMSI = boundSIM && boundSIM.imsi === this.currentSIM.imsi;
    const isMatchingICCID = boundSIM && boundSIM.iccid === this.currentSIM.iccid;

    if (isMatchingIMSI && isMatchingICCID && !this.currentSIM.isSuspicious) {
      status = 'REGISTERED_SECURE';
      threatScore = 0;
      logs.push('[SUCCESS] Hardware IMSI & ICCID match cryptographic Knox security enclave.');
      logs.push(`[SUCCESS] Registered Owner: ${this.boundProfile.ownerName} (${this.boundProfile.ownerEmail})`);
      logs.push(`[SUCCESS] Anti-SIM Swap Monitoring: ACTIVE | Token: ${this.boundProfile.securityToken}`);
      logs.push('[INFO] Baseband ciphering: 5G SA AES-256 GCM verified.');

      let finalRiskResult = null;
      if (RiskEngine) {
        finalRiskResult = RiskEngine.analyze({
          module: 'sim',
          indicators,
          metadata: { hasSim: true, registered: true, secure: true }
        });
      }

      return {
        status,
        threatScore: finalRiskResult ? finalRiskResult.score : threatScore,
        threatLevel: finalRiskResult ? (finalRiskResult.severity.charAt(0) + finalRiskResult.severity.slice(1).toLowerCase()) : 'Safe',
        logs,
        details: finalRiskResult ? finalRiskResult.indicators.map(i => ({
          type: (i.severity === 'HIGH' || i.severity === 'CRITICAL') ? 'danger' : 'warning',
          title: i.title,
          message: i.description
        })) : [],
        indicators: finalRiskResult ? finalRiskResult.indicators : indicators,
        verdict: finalRiskResult ? finalRiskResult.verdict : 'UNKNOWN',
        summary: finalRiskResult ? finalRiskResult.summary : '',
        currentSIM: this.currentSIM,
        boundProfile: this.boundProfile
      };
    } else {
      // MISMATCH OR SUSPICIOUS SIM SWAP ATTACK DETECTED!
      status = 'SIM_SWAP_ATTACK';
      threatScore = 95;
      logs.push('[CRITICAL] 🚨 CRITICAL TELECOM BREACH DETECTED: UNAUTHORIZED SIM SWAP / HIJACK!');
      logs.push(`[CRITICAL] Expected Bound IMSI: ${boundSIM ? boundSIM.imsi : 'UNKNOWN'}`);
      logs.push(`[CRITICAL] Detected Rogue IMSI: ${this.currentSIM.imsi}`);
      logs.push(`[CRITICAL] Expected Bound ICCID: ${boundSIM ? boundSIM.iccid : 'UNKNOWN'}`);
      logs.push(`[CRITICAL] Detected Rogue ICCID: ${this.currentSIM.iccid}`);
      logs.push('[ALERT] Cellular cryptographic binding failed. Threat siren activated!');

      details.push({
        type: 'danger',
        title: 'CRITICAL: Unauthorized SIM Swap / Port-Out Hijack',
        message: `An unrecognized SIM card (${this.currentSIM.carrier}, IMSI: ${this.currentSIM.imsi}) was inserted into this registered device without Knox authorization. Attackers use SIM swapping to intercept banking SMS 2FA codes and reset passwords.`
      });

      if (this.currentSIM.networkType.includes('2G') || this.currentSIM.networkType.includes('GSM')) {
        details.push({
          type: 'danger',
          title: 'Downgrade Attack / IMSI Catcher Vector',
          message: 'Cellular radio was forced down to unencrypted 2G/GSM protocol. Often indicative of a malicious Stingray / IMSI catcher interception.'
        });
        indicators.push({
          id: 'SIM_DOWNGRADE_ATTACK',
          category: 'BEHAVIOR',
          severity: 'HIGH',
          weight: 40,
          title: 'Downgrade Attack / IMSI Catcher Vector',
          description: 'Cellular radio was forced down to unencrypted 2G/GSM protocol.',
          evidence: `Network: ${this.currentSIM.networkType}`,
          recommendation: 'Move to a different location or force 5G/LTE only if possible.',
          source: 'LOCAL_HEURISTIC'
        });
      }

      let finalRiskResult = null;
      if (RiskEngine) {
        indicators.push({
          id: 'SIM_SWAP_HIJACK',
          category: 'IDENTITY',
          severity: 'CRITICAL',
          weight: 95,
          title: 'CRITICAL: Unauthorized SIM Swap / Port-Out Hijack',
          description: `An unrecognized SIM card (${this.currentSIM.carrier}, IMSI: ${this.currentSIM.imsi}) was inserted into this registered device without Knox authorization.`,
          evidence: `Expected IMSI: ${boundSIM ? boundSIM.imsi : 'UNKNOWN'} | Detected: ${this.currentSIM.imsi}`,
          recommendation: 'Contact your telecom provider immediately. Do not trust incoming SMS 2FA codes.',
          source: 'LOCAL_HEURISTIC'
        });

        finalRiskResult = RiskEngine.analyze({
          module: 'sim',
          indicators,
          metadata: { hasSim: true, registered: true, secure: false }
        });
      }

      return {
        status,
        threatScore: finalRiskResult ? finalRiskResult.score : threatScore,
        threatLevel: finalRiskResult ? (finalRiskResult.severity.charAt(0) + finalRiskResult.severity.slice(1).toLowerCase()) : 'Critical',
        logs,
        details: finalRiskResult ? finalRiskResult.indicators.map(i => ({
          type: (i.severity === 'HIGH' || i.severity === 'CRITICAL') ? 'danger' : 'warning',
          title: i.title,
          message: i.description
        })) : details,
        indicators: finalRiskResult ? finalRiskResult.indicators : indicators,
        verdict: finalRiskResult ? finalRiskResult.verdict : 'UNKNOWN',
        summary: finalRiskResult ? finalRiskResult.summary : '',
        currentSIM: this.currentSIM,
        boundProfile: this.boundProfile
      };
    }
  }

  /**
   * Generate a cryptographically secure random hex string of the given byte length.
   * Uses crypto.getRandomValues() instead of Math.random().
   */
  _secureRandomHex(byteLength) {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
  }

  /**
   * Derives a salted SHA-256 hash of the given PIN using Web Crypto.
   * Returns a Promise<{ salt: string, hash: string }>.
   * The raw PIN is never stored.
   */
  async _hashPIN(pin) {
    const salt = this._secureRandomHex(16); // 128-bit random salt
    const encoder = new TextEncoder();
    const data = encoder.encode(salt + pin);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
    return { salt, hash: hashHex };
  }

  /**
   * Verifies a raw PIN against the stored { salt, hash } record.
   * Returns a Promise<boolean>.
   */
  async _verifyPIN(pin, storedSalt, storedHash) {
    const encoder = new TextEncoder();
    const data = encoder.encode(storedSalt + pin);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
    return hashHex === storedHash;
  }

  /**
   * Register and bind the active SIM to the device.
   * Returns a Promise so that PIN hashing (async) is handled correctly.
   */
  async registerSIM(formData) {
    if (!this.currentSIM) {
      throw new Error('No active SIM card available to register.');
    }

    const rawPin = formData.securityPin || '1234';
    // Hash the PIN — never store plaintext
    const pinRecord = await this._hashPIN(rawPin);

    const registrationTimestamp = new Date().toISOString();

    // Cryptographically secure token generation
    const tokenHex = this._secureRandomHex(4);
    const tokenHex2 = this._secureRandomHex(4);
    const securityToken = `T&V-KNOX-${tokenHex}-${tokenHex2}`;

    const certHex = this._secureRandomHex(4);
    const certSerial = `CERT-${Date.now().toString(16).toUpperCase()}-${certHex}`;

    const newProfile = {
      ownerName: formData.ownerName || 'Authorized Device Owner',
      ownerEmail: formData.ownerEmail || 'user@trustandverify.com',
      emergencyPhone: formData.emergencyPhone || '+1 (555) 911-0000',
      deviceAssetTag: formData.deviceAssetTag || 'OEM-DEFENSE-PIXEL-9',
      // PIN is stored as { salt, hash } — NOT plaintext
      pinSalt: pinRecord.salt,
      pinHash: pinRecord.hash,
      antiSimSwapEnabled: formData.antiSimSwapEnabled !== false,
      autoCallScreening: formData.autoCallScreening !== false,
      roamingLockEnabled: formData.roamingLockEnabled || false,
      securityToken,
      certSerial,
      registeredAt: registrationTimestamp,
      hardwareIMEI: DEFAULT_HARDWARE_IMEI,
      enclaveId: DEFAULT_HARDWARE_ENCLAVE_ID,
      simDetails: { ...this.currentSIM, isSuspicious: false }
    };

    this.boundProfile = newProfile;
    localStorage.setItem(STORAGE_KEY_SIM_REGISTRATION, JSON.stringify(newProfile));

    return {
      success: true,
      profile: newProfile,
      evaluation: this.evaluateSIMSecurity()
    };
  }

  /**
   * Unbind / Reset registration.
   * Accepts a raw PIN and compares it against the stored hash.
   * Returns a Promise<{ success: boolean, error?: string, evaluation? }>
   */
  async unbindRegistration(providedPin) {
    if (this.boundProfile && this.boundProfile.pinHash) {
      // Verify against stored hash — never compare plaintexts
      if (!providedPin) {
        return { success: false, error: 'PIN is required to unbind SIM registration.' };
      }
      const isValid = await this._verifyPIN(
        providedPin,
        this.boundProfile.pinSalt,
        this.boundProfile.pinHash
      );
      if (!isValid) {
        return { success: false, error: 'Incorrect Security PIN. Cannot unbind SIM registration.' };
      }
    } else if (this.boundProfile && this.boundProfile.securityPin) {
      // Legacy plaintext PIN (profiles registered before Phase 0) — migrate on next registration
      if (providedPin && providedPin !== this.boundProfile.securityPin) {
        return { success: false, error: 'Incorrect Security PIN. Cannot unbind SIM registration.' };
      }
    }

    this.boundProfile = null;
    localStorage.removeItem(STORAGE_KEY_SIM_REGISTRATION);
    localStorage.removeItem(STORAGE_KEY_PIN_HASH);
    return { success: true, evaluation: this.evaluateSIMSecurity() };
  }
}

// Global instance
window.simRegistryEngine = new SIMRegistryEngine();
window.SIM_PRESETS = SIM_PRESETS;
