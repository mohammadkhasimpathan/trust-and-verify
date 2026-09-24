/**
 * callScanner.js
 * Analyzes phone numbers for scam history and contains logic/transcripts for the AI Call Interceptor simulation.
 */

// Blacklisted phone numbers representing simulated cyber threat calls
const CALLED_BLACKLIST = {
  '+18004771040': {
    name: 'IRS Spoofed Robocall',
    type: 'Gov Impersonation',
    threat: 'Critical',
    reports: 1429,
    carrier: 'VoIP Gateway Relay',
    location: 'Washington, D.C.',
    description: 'Frequently spoofed phone number mimicking the official IRS helpline. Delivers robocalls threatening arrest unless payment is made.'
  },
  '+18884492265': {
    name: 'Chase Fraud Support (Spoofed)',
    type: 'Bank Spoofing',
    threat: 'Critical',
    reports: 843,
    carrier: 'VoIP Carrier Corp',
    location: 'Columbus, OH',
    description: 'Spoofed Caller ID used to execute OTP bypass scams and bank transfer fraud.'
  },
  '+18552223940': {
    name: 'IRS Tax Audit Center (Fake)',
    type: 'Gov Impersonation',
    threat: 'High',
    reports: 341,
    carrier: 'Inteliquent VoIP',
    location: 'Washington, D.C.',
    description: 'Robocall targeting individuals, claiming their tax returns are under criminal investigation.'
  },
  '+13125550199': {
    name: 'Suspect Telemarketing Spam',
    type: 'Spam/Telemarketing',
    threat: 'Medium',
    reports: 120,
    carrier: 'Bandwidth.com VoIP',
    location: 'Chicago, IL',
    description: 'Unsolicited VOIP number executing mass robocalls regarding utility or insurance adjustments.'
  }
};

// Lists for deterministic name generation
const FIRST_NAMES = ['John', 'Jane', 'Michael', 'Emily', 'David', 'Sarah', 'Robert', 'Jessica', 'William', 'Karen', 'Richard', 'Nancy', 'Thomas', 'Lisa', 'Daniel', 'Betty', 'Matthew', 'Sandra', 'Anthony', 'Ashley', 'Joseph', 'Kimberly', 'Mark', 'Donna', 'Donald', 'Carol', 'Steven', 'Michelle', 'Paul', 'Emily', 'Andrew', 'Amanda', 'Joshua', 'Melissa', 'Kenneth', 'Deborah', 'Kevin', 'Stephanie', 'Brian', 'Rebecca', 'George', 'Sharon', 'Edward', 'Cynthia', 'Ronald', 'Kathleen', 'Timothy', 'Amy', 'Jason', 'Shirley'];
const LAST_NAMES = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez', 'Wilson', 'Anderson', 'Thomas', 'Taylor', 'Moore', 'Jackson', 'Martin', 'Lee', 'Perez', 'Thompson', 'White', 'Harris', 'Sanchez', 'Clark', 'Ramirez', 'Lewis', 'Robinson', 'Walker', 'Young', 'Allen', 'King', 'Wright', 'Scott', 'Torres', 'Nguyen', 'Hill', 'Flores', 'Green', 'Adams', 'Nelson', 'Baker', 'Hall', 'Rivera', 'Campbell', 'Mitchell', 'Carter', 'Roberts'];

const AREA_CODES = {
  '201': 'Jersey City, NJ',
  '202': 'Washington, D.C.',
  '203': 'Bridgeport, CT',
  '205': 'Birmingham, AL',
  '206': 'Seattle, WA',
  '207': 'Portland, ME',
  '212': 'New York, NY',
  '213': 'Los Angeles, CA',
  '214': 'Dallas, TX',
  '215': 'Philadelphia, PA',
  '216': 'Cleveland, OH',
  '217': 'Springfield, IL',
  '218': 'Duluth, MN',
  '302': 'Wilmington, DE',
  '303': 'Denver, CO',
  '305': 'Miami, FL',
  '310': 'Los Angeles, CA',
  '312': 'Chicago, IL',
  '313': 'Detroit, MI',
  '404': 'Atlanta, GA',
  '415': 'San Francisco, CA',
  '503': 'Portland, OR',
  '512': 'Austin, TX',
  '602': 'Phoenix, AZ',
  '617': 'Boston, MA',
  '619': 'San Diego, CA',
  '650': 'Mountain View, CA',
  '702': 'Las Vegas, NV',
  '808': 'Honolulu, HI',
  '901': 'Memphis, TN',
  '917': 'New York, NY'
};

const CARRIERS = [
  'Verizon Wireless', 
  'T-Mobile USA', 
  'AT&T Mobility', 
  'Google Voice', 
  'Bandwidth.com VoIP', 
  'Comcast Cable', 
  'Spectrum Mobile',
  'Lumen Technologies',
  'UScellular'
];

// Helper hash function to get deterministic index
function getDeterministicIndex(str, max) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  return Math.abs(hash) % max;
}

function analyzePhoneNumber(numberStr) {
  const logs = [];
  const details = [];
  let score = 0;
  let callerProfile = null;

  if (!numberStr) {
    return {
      threatLevel: 'Unknown',
      score: 0,
      logs: ['[ERROR] No number entered for scanning.'],
      details: [],
      callerProfile: null
    };
  }

  // Clean the number format (remove dashes, spaces, parentheses)
  const cleanNumber = numberStr.replace(/[\s\-\(\)]/g, '');
  logs.push(`[INFO] Formatting phone number: ${cleanNumber}`);

  // Checks
  if (CALLED_BLACKLIST[cleanNumber]) {
    const entry = CALLED_BLACKLIST[cleanNumber];
    score = 100;
    logs.push(`[CRITICAL] PHONE NUMBER FOUND IN THREAT BLACKLIST!`);
    logs.push(`[CRITICAL] Identifier: ${entry.name} (${entry.type})`);
    details.push({
      type: 'danger',
      title: `Blacklist Match: ${entry.name}`,
      message: `Verified threat matching phone records database. ${entry.reports} reports logged. Description: ${entry.description}`
    });

    callerProfile = {
      name: entry.name,
      type: entry.type,
      status: 'DANGER / BLOCKLISTED',
      statusClass: 'danger',
      number: numberStr,
      carrier: entry.carrier,
      location: entry.location,
      reports: entry.reports,
      email: entry.name.toLowerCase().replace(/[^a-z0-9]/g, '') + '@security-alert.org',
      description: entry.description,
      avatar: '🚨'
    };
  } else if (cleanNumber === '+16502530000') {
    logs.push(`[OK] Number verified as Google HQ Main Line.`);
    callerProfile = {
      name: 'Google LLC (HQ)',
      type: 'Corporate Headquarters',
      status: 'VERIFIED SAFE',
      statusClass: 'safe',
      number: numberStr,
      carrier: 'Verizon Business',
      location: 'Mountain View, CA',
      reports: 0,
      email: 'workspace-noreply@google.com',
      description: 'Verified public headquarters number for Google LLC. This number is safe.',
      avatar: '✅'
    };
  } else {
    logs.push(`[OK] Number not found in blacklist database.`);
    
    // Check if it's a suspicious format (e.g. fake local matching prefix or invalid length)
    if (cleanNumber.length < 7) {
      score += 25;
      logs.push(`[WARN] Invalid phone number structure.`);
      details.push({
        type: 'warning',
        title: 'Malformed Number Structure',
        message: 'The phone number has too few digits, indicating it is likely generated by custom VOIP spoofing software.'
      });
    }

    // VOIP / Caller ID Spoof Check
    const voipPrefixes = ['+1800', '+1888', '+1877', '+1866', '+1855', '+1844'];
    let prefixMatched = null;
    for (const prefix of voipPrefixes) {
      if (cleanNumber.startsWith(prefix)) {
        prefixMatched = prefix;
        break;
      }
    }

    if (prefixMatched) {
      score += 35;
      logs.push(`[WARN] Toll-Free VOIP relay prefix detected (${prefixMatched}).`);
      details.push({
        type: 'warning',
        title: 'Toll-Free VOIP Gateway',
        message: 'The number originates from a toll-free VoIP prefix. VoIP gateways are easily rented online by scammers to obfuscate geographic location.'
      });
    }

    // Generate deterministic rich profile
    const fIdx = getDeterministicIndex(cleanNumber + "first", FIRST_NAMES.length);
    const lIdx = getDeterministicIndex(cleanNumber + "last", LAST_NAMES.length);
    const firstName = FIRST_NAMES[fIdx];
    const lastName = LAST_NAMES[lIdx];
    const fullName = `${firstName} ${lastName}`;

    let detectedLocation = 'Unknown Region';
    const match = cleanNumber.match(/^(?:\+?1)?(\d{3})/);
    if (match && AREA_CODES[match[1]]) {
      detectedLocation = AREA_CODES[match[1]];
    } else if (cleanNumber.startsWith('+91')) {
      detectedLocation = 'New Delhi, India';
    } else if (cleanNumber.startsWith('+44')) {
      detectedLocation = 'London, United Kingdom';
    }

    const cIdx = getDeterministicIndex(cleanNumber + "carrier", CARRIERS.length);
    const carrier = CARRIERS[cIdx];

    let status = 'VERIFIED / SAFE';
    let statusClass = 'safe';
    let avatar = '👤';
    let reports = 0;
    let description = `This subscriber is registered in ${detectedLocation}. No threat record found in global threat indexes.`;

    if (score >= 50) {
      status = 'SUSPICIOUS VoIP';
      statusClass = 'warning';
      avatar = '⚠️';
      reports = getDeterministicIndex(cleanNumber + "reports", 12) + 2;
      description = `This VoIP gateway originates from ${detectedLocation} and shows bulk telemarketing characteristics. Spam reports filed: ${reports}.`;
    } else if (score >= 25) {
      status = 'UNKNOWN / POOR FORMAT';
      statusClass = 'warning';
      avatar = '⚠️';
      reports = getDeterministicIndex(cleanNumber + "reports", 3) + 1;
      description = `The number structure indicates a non-standard local routing layout. Use caution before answering.`;
    }

    callerProfile = {
      name: cleanNumber.length < 7 ? 'Invalid Caller' : fullName,
      type: cleanNumber.length < 7 ? 'Malformed Route' : (score >= 50 ? 'VoIP Line' : 'Mobile / Landline'),
      status,
      statusClass,
      number: numberStr,
      carrier,
      location: detectedLocation,
      reports,
      email: cleanNumber.length < 7 ? 'unknown@caller.id' : `${firstName.toLowerCase()}.${lastName.toLowerCase()}@gmail.com`,
      description,
      avatar
    };
  }

  // Determine threat level based on score
  let threatLevel = 'Safe';
  if (score >= 80) {
    threatLevel = 'Critical';
  } else if (score >= 50) {
    threatLevel = 'High';
  } else if (score >= 25) {
    threatLevel = 'Medium';
  } else if (score > 0) {
    threatLevel = 'Low';
  }

  return {
    threatLevel,
    score,
    logs,
    details,
    callerProfile
  };
}

// Dialog transcripts for the AI Interceptor Simulation
const INTERCEPTOR_SCENARIOS = {
  irs: {
    title: 'IRS Arrest Robocall Impersonation',
    number: '+1 (800) 477-1040',
    type: 'Gov Impersonation',
    script: [
      { speaker: 'caller', text: 'Hello, this is Agent Vance calling from the IRS Enforcement Division. We have a federal warrant for your arrest due to tax evasion.' },
      { speaker: 'ai', text: '[Trust & Verify Interceptor Activated] Connection secure. Please state your department credential ID and case authorization code, Agent Vance.' },
      { speaker: 'caller', text: 'Listen to me, you need to pay a penalty of $4,500 immediately via gift cards or wire transfer to avoid police dispatch to your house.' },
      { speaker: 'ai', text: '[ANALYZING THREAT...] Trigger: Request for payment via gift cards/wire. Under IRS protocol, all tax notices are mailed via USPS. No officer requests cards.' },
      { speaker: 'caller', text: 'If you do not cooperate immediately, a sheriff will be at your door in 10 minutes!' },
      { speaker: 'ai', text: '[DETECTED SYSTEMIC SCAM] Verification failed. Threat threat rating: Critical. Logged IP and relay route. Disconnecting.' }
    ]
  },
  bank: {
    title: 'Bank Fraud Alert (OTP Password Bypass)',
    number: '+1 (888) 449-2265',
    type: 'Financial Fraud',
    script: [
      { speaker: 'caller', text: 'Hello, this is Chase Bank fraud support. We detected a suspicious card charge of $1,200 at Ohio Walmart.' },
      { speaker: 'ai', text: '[Trust & Verify Interceptor Activated] Connecting secure bank filter. Please provide the merchant transaction routing ID, please.' },
      { speaker: 'caller', text: 'We blocked it, but to secure your funds, we sent a 6-digit verification code to your cell. Please read it to me to authorize security.' },
      { speaker: 'ai', text: '[ANALYZING THREAT...] Trigger: Request for OTP verification code. Passcodes are used to AUTHORIZE funds transfer or reset passwords, never to verify identity.' },
      { speaker: 'caller', text: 'Sir, if you do not read the code, we cannot lock your account and your funds will be lost.' },
      { speaker: 'ai', text: '[DETECTED FRAUD VECTOR] Request for security passcode is a known credential harvesting vector. Terminating call.' }
    ]
  },
  family: {
    title: 'Grandparent Crisis Emergency Phishing',
    number: '+1 (312) 555-0105',
    type: 'Social Engineering',
    script: [
      { speaker: 'caller', text: 'Grandma? It\'s me. I\'m in jail after a car accident. I need $2,000 wired immediately for bail, please don\'t tell mom!' },
      { speaker: 'ai', text: '[Trust & Verify Interceptor Activated] Emergency scam filter active. Please answer family verification prompt: What is your family pet\'s name?' },
      { speaker: 'caller', text: 'What? I don\'t have time for this, the lawyer is waiting. Please wire the money via Western Union right now!' },
      { speaker: 'ai', text: '[ANALYZING THREAT...] Trigger: Urgency coercion, wire request, and failure of verification prompt. Scam correlation: 95%.' },
      { speaker: 'caller', text: 'Why are you being like this? I\'m in trouble!' },
      { speaker: 'ai', text: '[DETECTED IDENTITY FRAUD] Emotional coercion signature detected. Logging voice biometric markers for blocking list. Disconnecting.' }
    ]
  }
};

// Support both CommonJS node environment and global browser export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyzePhoneNumber, INTERCEPTOR_SCENARIOS, CALLED_BLACKLIST };
} else {
  window.analyzePhoneNumber = analyzePhoneNumber;
  window.INTERCEPTOR_SCENARIOS = INTERCEPTOR_SCENARIOS;
  window.CALLED_BLACKLIST = CALLED_BLACKLIST;
}
