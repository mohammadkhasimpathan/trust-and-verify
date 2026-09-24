const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const otplib = require('otplib');
const db = require('../db/connection');
const rateLimit = require('express-rate-limit');
const { sendEmail } = require('../email/emailService');
const { logSecurityEvent } = require('../security/securityLogger');
const { requireAuth } = require('./authMiddleware');

const router = express.Router();

const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5,
  message: { error: 'Too many attempts, please try again later.' }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 10,
  message: { error: 'Too many attempts, please try again later.' }
});

// Helper: Generate secure tokens
function generateSecureToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Session Creation Helper
function createSession(req, userId) {
  const sessionId = uuidv4();
  const deviceLabel = req.headers['user-agent'] || 'Unknown Device';
  // Keep the session token in the DB
  db.prepare(`
    INSERT INTO user_sessions (id, user_id, device_label, expires_at)
    VALUES (?, ?, ?, datetime('now', '+7 days'))
  `).run(sessionId, userId, deviceLabel);
  
  // Set req.session
  req.session.userId = userId;
  req.session.sessionId = sessionId;
}

// ─── REGISTRATION & EMAIL VERIFICATION ────────────────────────────────────

router.post('/register', strictLimiter, async (req, res) => {
  const { email, password, displayName } = req.body;
  if (!email || !password || password.length < 8) {
    return res.status(400).json({ error: 'Valid email and password (min 8 chars) required.' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(normalizedEmail);
    if (existing) {
      // Don't leak existing account
      return res.status(400).json({ error: 'Registration failed.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const userId = uuidv4();
    
    // Verification Token
    const rawToken = generateSecureToken();
    const tokenHash = hashToken(rawToken);

    db.transaction(() => {
      db.prepare(`
        INSERT INTO users (id, email, password_hash)
        VALUES (?, ?, ?)
      `).run(userId, normalizedEmail, passwordHash);

      db.prepare(`
        INSERT INTO user_profiles (user_id, display_name)
        VALUES (?, ?)
      `).run(userId, displayName || normalizedEmail.split('@')[0]);

      db.prepare(`
        INSERT INTO auth_tokens (id, user_id, token_hash, token_type, expires_at)
        VALUES (?, ?, ?, 'EMAIL_VERIFICATION', datetime('now', '+1 day'))
      `).run(uuidv4(), userId, tokenHash);
    })();

    const verifyUrl = `${req.protocol}://${req.get('host')}/verify-email?token=${rawToken}`;
    
    await sendEmail({
      to: normalizedEmail,
      subject: 'Trust & Verify - Verify your email',
      text: `Please verify your email by opening this link: ${verifyUrl}`
    });

    logSecurityEvent(userId, 'REGISTER', true, req);

    res.json({ success: true, message: 'Account created. Please verify your email.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

router.post('/verify-email', strictLimiter, (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required.' });

  try {
    const tokenHash = hashToken(token);
    const dbToken = db.prepare(`
      SELECT * FROM auth_tokens 
      WHERE token_hash = ? AND token_type = 'EMAIL_VERIFICATION' AND is_used = 0 AND expires_at > datetime('now')
    `).get(tokenHash);

    if (!dbToken) {
      return res.status(400).json({ error: 'Invalid or expired token.' });
    }

    db.transaction(() => {
      db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(dbToken.user_id);
      db.prepare('UPDATE auth_tokens SET is_used = 1 WHERE id = ?').run(dbToken.id);
    })();

    logSecurityEvent(dbToken.user_id, 'EMAIL_VERIFIED', true, req);
    res.json({ success: true, message: 'Email verified successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Internal error.' });
  }
});

// ─── LOGIN ─────────────────────────────────────────────────────────────

router.post('/login', loginLimiter, async (req, res) => {
  const { email, password, totp } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const user = db.prepare(`
      SELECT u.id, u.password_hash, m.secret_encrypted, m.is_enabled as mfa_enabled
      FROM users u
      LEFT JOIN mfa_secrets m ON u.id = m.user_id
      WHERE u.email = ?
    `).get(normalizedEmail);

    if (!user) {
      logSecurityEvent(null, 'LOGIN_FAILURE', false, req, { email: normalizedEmail });
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      logSecurityEvent(user.id, 'LOGIN_FAILURE', false, req);
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    if (user.mfa_enabled) {
      if (!totp) {
        return res.status(403).json({ error: 'MFA_REQUIRED', message: 'MFA code is required.' });
      }

      // We decrypt the secret here (assuming it's just base32 for this implementation, 
      // but typically we'd AES encrypt it in the DB).
      // For simplicity in Phase 8 without a complex KMS, we assume secret_encrypted holds the base32 secret.
      const isValid = otplib.authenticator.verify({ token: totp, secret: user.secret_encrypted });
      
      if (!isValid) {
        // Check backup codes
        const codeHash = hashToken(totp);
        const backup = db.prepare('SELECT id FROM mfa_backup_codes WHERE user_id = ? AND code_hash = ? AND is_used = 0').get(user.id, codeHash);
        
        if (backup) {
          db.prepare('UPDATE mfa_backup_codes SET is_used = 1, used_at = CURRENT_TIMESTAMP WHERE id = ?').run(backup.id);
        } else {
          logSecurityEvent(user.id, 'MFA_FAILURE', false, req);
          return res.status(401).json({ error: 'Invalid MFA code.' });
        }
      }
    }

    // Regenerate session to prevent fixation
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error.' });
      
      db.prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
      createSession(req, user.id);
      
      logSecurityEvent(user.id, 'LOGIN_SUCCESS', true, req);
      res.json({ success: true, message: 'Login successful.' });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ─── PASSWORD RESET ────────────────────────────────────────────────────

router.post('/forgot-password', strictLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });
  
  const normalizedEmail = email.toLowerCase().trim();
  
  try {
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(normalizedEmail);
    if (user) {
      const rawToken = generateSecureToken();
      const tokenHash = hashToken(rawToken);

      db.prepare(`
        INSERT INTO auth_tokens (id, user_id, token_hash, token_type, expires_at)
        VALUES (?, ?, ?, 'PASSWORD_RESET', datetime('now', '+30 minutes'))
      `).run(uuidv4(), user.id, tokenHash);

      const resetUrl = `${req.protocol}://${req.get('host')}/reset-password?token=${rawToken}`;
      await sendEmail({
        to: normalizedEmail,
        subject: 'Trust & Verify - Password Reset',
        text: `Reset your password here: ${resetUrl}`
      });
      
      logSecurityEvent(user.id, 'PASSWORD_RESET_REQUESTED', true, req);
    }
    
    // Generic response
    res.json({ success: true, message: 'If an account exists for this email, recovery instructions have been sent.' });
  } catch (err) {
    res.status(500).json({ error: 'Internal error.' });
  }
});

router.post('/reset-password', strictLimiter, async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'Invalid request.' });
  }

  try {
    const tokenHash = hashToken(token);
    const dbToken = db.prepare(`
      SELECT * FROM auth_tokens 
      WHERE token_hash = ? AND token_type = 'PASSWORD_RESET' AND is_used = 0 AND expires_at > datetime('now')
    `).get(tokenHash);

    if (!dbToken) {
      return res.status(400).json({ error: 'Invalid or expired token.' });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);

    db.transaction(() => {
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, dbToken.user_id);
      db.prepare('UPDATE auth_tokens SET is_used = 1 WHERE id = ?').run(dbToken.id);
      
      // Invalidate all sessions
      db.prepare('DELETE FROM user_sessions WHERE user_id = ?').run(dbToken.user_id);
    })();

    logSecurityEvent(dbToken.user_id, 'PASSWORD_RESET_COMPLETED', true, req);
    res.json({ success: true, message: 'Password reset successful. Please log in again.' });
  } catch (err) {
    res.status(500).json({ error: 'Internal error.' });
  }
});

router.post('/change-password', requireAuth, strictLimiter, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'Invalid request.' });
  }
  
  try {
    const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.session.userId);
    const match = await bcrypt.compare(currentPassword, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Incorrect current password.' });
    
    const passwordHash = await bcrypt.hash(newPassword, 12);
    db.transaction(() => {
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, req.session.userId);
      // Revoke other sessions
      db.prepare('DELETE FROM user_sessions WHERE user_id = ? AND id != ?').run(req.session.userId, req.session.sessionId);
    })();
    
    logSecurityEvent(req.session.userId, 'PASSWORD_CHANGED', true, req);
    res.json({ success: true, message: 'Password changed successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Internal error.' });
  }
});

// ─── MFA (TOTP) ────────────────────────────────────────────────────────

router.post('/mfa/setup', requireAuth, strictLimiter, (req, res) => {
  try {
    const secret = otplib.authenticator.generateSecret();
    const user = db.prepare('SELECT email FROM users WHERE id = ?').get(req.session.userId);
    const otpauth = otplib.authenticator.keyuri(user.email, 'TrustVerify', secret);
    
    // Store temporarily unenabled
    db.prepare(`
      INSERT INTO mfa_secrets (user_id, secret_encrypted, is_enabled)
      VALUES (?, ?, 0)
      ON CONFLICT(user_id) DO UPDATE SET secret_encrypted = excluded.secret_encrypted, is_enabled = 0
    `).run(req.session.userId, secret);
    
    res.json({ secret, otpauth });
  } catch (err) {
    res.status(500).json({ error: 'Internal error.' });
  }
});

router.post('/mfa/verify', requireAuth, strictLimiter, (req, res) => {
  const { totp } = req.body;
  try {
    const mfa = db.prepare('SELECT secret_encrypted FROM mfa_secrets WHERE user_id = ? AND is_enabled = 0').get(req.session.userId);
    if (!mfa) return res.status(400).json({ error: 'MFA setup not initiated.' });
    
    const isValid = otplib.authenticator.verify({ token: totp, secret: mfa.secret_encrypted });
    if (!isValid) return res.status(400).json({ error: 'Invalid code.' });
    
    // Generate backup codes
    const backupCodes = [];
    const backupHashes = [];
    for (let i=0; i<8; i++) {
      const code = crypto.randomBytes(4).toString('hex');
      backupCodes.push(code);
      backupHashes.push(hashToken(code));
    }
    
    db.transaction(() => {
      db.prepare('UPDATE mfa_secrets SET is_enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?').run(req.session.userId);
      db.prepare('DELETE FROM mfa_backup_codes WHERE user_id = ?').run(req.session.userId);
      
      const insertBackup = db.prepare('INSERT INTO mfa_backup_codes (id, user_id, code_hash) VALUES (?, ?, ?)');
      for (const hash of backupHashes) {
        insertBackup.run(uuidv4(), req.session.userId, hash);
      }
    })();
    
    logSecurityEvent(req.session.userId, 'MFA_ENABLED', true, req);
    res.json({ success: true, backupCodes, message: 'MFA enabled successfully. Save your backup codes.' });
  } catch (err) {
    res.status(500).json({ error: 'Internal error.' });
  }
});

router.post('/mfa/disable', requireAuth, strictLimiter, async (req, res) => {
  const { password, totp } = req.body;
  
  try {
    const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.session.userId);
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid password.' });
    
    const mfa = db.prepare('SELECT secret_encrypted FROM mfa_secrets WHERE user_id = ? AND is_enabled = 1').get(req.session.userId);
    if (!mfa) return res.status(400).json({ error: 'MFA is not enabled.' });
    
    const isValid = otplib.authenticator.verify({ token: totp, secret: mfa.secret_encrypted });
    if (!isValid) {
      logSecurityEvent(req.session.userId, 'MFA_DISABLE_FAILURE', false, req);
      return res.status(401).json({ error: 'Invalid TOTP code.' });
    }
    
    db.transaction(() => {
      db.prepare('DELETE FROM mfa_secrets WHERE user_id = ?').run(req.session.userId);
      db.prepare('DELETE FROM mfa_backup_codes WHERE user_id = ?').run(req.session.userId);
    })();
    
    logSecurityEvent(req.session.userId, 'MFA_DISABLED', true, req);
    res.json({ success: true, message: 'MFA disabled.' });
  } catch (err) {
    res.status(500).json({ error: 'Internal error.' });
  }
});

// ─── SESSION MANAGEMENT ────────────────────────────────────────────────

router.get('/sessions', requireAuth, (req, res) => {
  try {
    // Update last seen
    if (req.session.sessionId) {
      db.prepare('UPDATE user_sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE id = ?').run(req.session.sessionId);
    }
    
    const sessions = db.prepare('SELECT id, device_label, created_at, last_seen_at FROM user_sessions WHERE user_id = ?').all(req.session.userId);
    
    res.json({
      success: true,
      sessions: sessions.map(s => ({
        id: s.id,
        deviceLabel: s.device_label,
        createdAt: s.created_at,
        lastSeenAt: s.last_seen_at,
        current: s.id === req.session.sessionId
      }))
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal error.' });
  }
});

router.post('/sessions/:id/revoke', requireAuth, (req, res) => {
  try {
    const result = db.prepare('DELETE FROM user_sessions WHERE id = ? AND user_id = ?').run(req.params.id, req.session.userId);
    if (result.changes > 0) {
      logSecurityEvent(req.session.userId, 'SESSION_REVOKED', true, req, { sessionId: req.params.id });
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error.' });
  }
});

router.post('/sessions/revoke-others', requireAuth, (req, res) => {
  try {
    db.prepare('DELETE FROM user_sessions WHERE user_id = ? AND id != ?').run(req.session.userId, req.session.sessionId);
    logSecurityEvent(req.session.userId, 'ALL_SESSIONS_REVOKED', true, req);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal error.' });
  }
});

// ─── SECURITY EVENTS ───────────────────────────────────────────────────

router.get('/security-events', requireAuth, (req, res) => {
  try {
    const events = db.prepare(`
      SELECT event_type, created_at, ip_metadata, user_agent_metadata, success 
      FROM security_events 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT 20
    `).all(req.session.userId);
    
    res.json({ success: true, events });
  } catch (err) {
    res.status(500).json({ error: 'Internal error.' });
  }
});

// ─── GENERAL SESSION GETTER ────────────────────────────────────────────

router.get('/session', (req, res) => {
  if (req.session && req.session.userId) {
    // Validate session in DB
    const dbSession = db.prepare('SELECT id FROM user_sessions WHERE id = ?').get(req.session.sessionId);
    if (!dbSession) {
      req.session.destroy();
      return res.status(401).json({ error: 'Session revoked.' });
    }
    
    const profile = db.prepare(`
      SELECT u.email, u.email_verified, u.created_at, p.display_name, p.language, p.theme,
             (SELECT COUNT(*) FROM mfa_secrets WHERE user_id = u.id AND is_enabled = 1) as mfa_enabled
      FROM users u
      JOIN user_profiles p ON u.id = p.user_id
      WHERE u.id = ?
    `).get(req.session.userId);

    if (!profile) {
      req.session.destroy();
      return res.status(401).json({ error: 'Session invalid.' });
    }
    
    return res.json({
      authenticated: true,
      user: {
        email: profile.email,
        email_verified: !!profile.email_verified,
        mfa_enabled: !!profile.mfa_enabled,
        displayName: profile.display_name,
        language: profile.language,
        theme: profile.theme,
        createdAt: profile.created_at
      }
    });
  }
  res.json({ authenticated: false });
});

router.post('/logout', (req, res) => {
  if (req.session.sessionId) {
    db.prepare('DELETE FROM user_sessions WHERE id = ?').run(req.session.sessionId);
  }
  logSecurityEvent(req.session.userId, 'LOGOUT', true, req);
  
  req.session.destroy();
  res.clearCookie('connect.sid');
  res.json({ success: true });
});

router.delete('/account', requireAuth, async (req, res) => {
  try {
    logSecurityEvent(req.session.userId, 'ACCOUNT_DELETED', true, req);
    db.prepare('DELETE FROM users WHERE id = ?').run(req.session.userId);
    req.session.destroy();
    res.clearCookie('connect.sid');
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;
