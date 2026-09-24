/**
 * simRegistry.js
 * Core Telecom & SIM Security Registry Engine for Trust & Verify.
 * Manages OEM Pre-Installed device states, SIM insertion/activation events,
 * cryptographic SIM binding, anti-SIM swap attack detection, and telecom telemetry.
 */

const STORAGE_KEY_SIM_REGISTRATION = 'trust_verify_sim_reg';
const STORAGE_KEY_OEM_CONFIG = 'trust_verify_oem_config';

// Default mock hardware specs
const DEFAULT_HARDWARE_IMEI = '358924091823901';
const DEFAULT_HARDWARE_ENCLAVE_ID = 'KNOX-SEC-ENCLAVE-994A-FF02';

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
    let threatScore = 0;
    let status = 'UNREGISTERED'; // 'NO_SIM', 'UNREGISTERED', 'REGISTERED_SECURE', 'SIM_SWAP_ATTACK'

    logs.push('[TELECOM_DAEMON] Scanning cellular baseband & hardware SIM socket...');

    if (!this.currentSIM) {
      status = 'NO_SIM';
      logs.push('[WARN] SIM Socket 1 is EMPTY. Cellular radio offline.');
      return {
        status,
        threatScore: 0,
        threatLevel: 'Low',
        logs,
        details: [{
          type: 'warning',
          title: 'No SIM Card Detected',
          message: 'Device has no active SIM card inserted. Insert and activate a SIM card to configure cellular cyber protection.'
        }],
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

      return {
        status,
        threatScore,
        threatLevel: 'Low',
        logs,
        details,
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

      return {
        status,
        threatScore,
        threatLevel: 'Safe',
        logs,
        details: [],
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
      }

      return {
        status,
        threatScore,
        threatLevel: 'Critical',
        logs,
        details,
        currentSIM: this.currentSIM,
        boundProfile: this.boundProfile
      };
    }
  }

  /**
   * Register and bind the active SIM to the device
   */
  registerSIM(formData) {
    if (!this.currentSIM) {
      throw new Error('No active SIM card available to register.');
    }

    const registrationTimestamp = new Date().toISOString();
    const tokenPart1 = Math.random().toString(36).substring(2, 6).toUpperCase();
    const tokenPart2 = Math.random().toString(36).substring(2, 6).toUpperCase();
    const securityToken = `T&V-KNOX-${tokenPart1}-${tokenPart2}`;
    const certSerial = `CERT-${Date.now().toString(16).toUpperCase()}-${Math.floor(Math.random() * 9999)}`;

    const newProfile = {
      ownerName: formData.ownerName || 'Authorized Device Owner',
      ownerEmail: formData.ownerEmail || 'user@trustandverify.com',
      emergencyPhone: formData.emergencyPhone || '+1 (555) 911-0000',
      deviceAssetTag: formData.deviceAssetTag || 'OEM-DEFENSE-PIXEL-9',
      securityPin: formData.securityPin || '1234',
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
   * Unbind / Reset registration
   */
  unbindRegistration(providedPin) {
    if (this.boundProfile && this.boundProfile.securityPin) {
      if (providedPin && providedPin !== this.boundProfile.securityPin) {
        return { success: false, error: 'Incorrect Security PIN. Cannot unbind SIM registration.' };
      }
    }

    this.boundProfile = null;
    localStorage.removeItem(STORAGE_KEY_SIM_REGISTRATION);
    return { success: true, evaluation: this.evaluateSIMSecurity() };
  }
}

// Global instance
window.simRegistryEngine = new SIMRegistryEngine();
window.SIM_PRESETS = SIM_PRESETS;
