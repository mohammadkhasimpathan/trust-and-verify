/**
 * qrAnalyzer.js
 * Identifies the payload type of a decoded QR code and delegates to URL analyzer if appropriate.
 */

const { SEVERITY, CATEGORY, SOURCE } = (typeof window !== 'undefined' && window.RiskTypes) ? window.RiskTypes : require('../core/riskTypes');

class QrAnalyzer {
  static analyze(decodedText) {
    const indicators = [];
    let qrType = 'UNKNOWN';
    let urlPayload = null;

    if (decodedText.startsWith('http://') || decodedText.startsWith('https://')) {
      qrType = 'URL';
      urlPayload = decodedText;
      indicators.push({
        id: 'QR_URL',
        category: CATEGORY.CONTENT,
        severity: SEVERITY.INFO,
        weight: 0,
        source: SOURCE.LOCAL_HEURISTIC,
        title: 'URL QR Code',
        description: 'This QR code contains a URL link.',
        evidence: decodedText,
        recommendation: 'Ensure the destination is safe before visiting.'
      });
    } else if (decodedText.startsWith('WIFI:')) {
      qrType = 'WIFI';
      indicators.push({
        id: 'QR_WIFI_CREDENTIALS',
        category: CATEGORY.NETWORK,
        severity: SEVERITY.MEDIUM,
        weight: 20,
        source: SOURCE.LOCAL_HEURISTIC,
        title: 'Wi-Fi Configuration',
        description: 'This QR code configures a Wi-Fi network.',
        evidence: 'Hidden for security',
        recommendation: 'Do not connect to unknown networks.'
      });
    } else if (decodedText.toLowerCase().startsWith('upi://')) {
      qrType = 'PAYMENT';
      indicators.push({
        id: 'QR_PAYMENT_URI',
        category: CATEGORY.CONTENT,
        severity: SEVERITY.MEDIUM,
        weight: 30,
        source: SOURCE.LOCAL_HEURISTIC,
        title: 'Payment URI Detected',
        description: 'This QR code initiates a payment transaction.',
        evidence: decodedText.substring(0, 30) + '...',
        recommendation: 'Verify the payee details independently before transferring funds.'
      });
    } else if (decodedText.startsWith('SMSTO:') || decodedText.startsWith('sms:')) {
      qrType = 'SMS';
      indicators.push({
        id: 'QR_SMS_ACTION',
        category: CATEGORY.CONTENT,
        severity: SEVERITY.LOW,
        weight: 10,
        source: SOURCE.LOCAL_HEURISTIC,
        title: 'SMS Action',
        description: 'This QR code prepares an SMS message.',
        evidence: decodedText.substring(0, 30) + '...',
        recommendation: 'Review the message content and recipient before sending.'
      });
    } else if (decodedText.startsWith('TEL:') || decodedText.startsWith('tel:')) {
      qrType = 'PHONE';
      indicators.push({
        id: 'QR_PHONE_ACTION',
        category: CATEGORY.CONTENT,
        severity: SEVERITY.LOW,
        weight: 10,
        source: SOURCE.LOCAL_HEURISTIC,
        title: 'Phone Action',
        description: 'This QR code prepares a phone call.',
        evidence: decodedText.substring(0, 30) + '...',
        recommendation: 'Verify the number before dialing.'
      });
    } else if (decodedText.includes('BEGIN:VCARD')) {
      qrType = 'CONTACT';
      indicators.push({
        id: 'QR_CONTACT_DATA',
        category: CATEGORY.CONTENT,
        severity: SEVERITY.INFO,
        weight: 0,
        source: SOURCE.LOCAL_HEURISTIC,
        title: 'Contact Card',
        description: 'This QR code contains contact information.',
        evidence: 'vCard Data',
        recommendation: 'Review contact details before saving.'
      });
    } else {
      qrType = 'TEXT';
      indicators.push({
        id: 'QR_UNKNOWN_PAYLOAD',
        category: CATEGORY.CONTENT,
        severity: SEVERITY.INFO,
        weight: 0,
        source: SOURCE.LOCAL_HEURISTIC,
        title: 'Plain Text Payload',
        description: 'This QR code contains generic text.',
        evidence: decodedText.substring(0, 50) + (decodedText.length > 50 ? '...' : ''),
        recommendation: 'None.'
      });
    }

    return { indicators, type: qrType, urlPayload, rawText: decodedText };
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = QrAnalyzer;
} else {
  window.QrAnalyzer = QrAnalyzer;
}
