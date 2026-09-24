const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/connection');
const rateLimit = require('express-rate-limit');

const router = express.Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5,
  message: { error: 'Too many authentication attempts, please try again later.' }
});

router.post('/register', authLimiter, async (req, res) => {
  const { email, password, displayName } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(normalizedEmail);
    if (existing) {
      // Return generic response to avoid email enumeration
      return res.status(400).json({ error: 'Registration failed.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const userId = uuidv4();
    
    db.transaction(() => {
      db.prepare(`
        INSERT INTO users (id, email, password_hash)
        VALUES (?, ?, ?)
      `).run(userId, normalizedEmail, passwordHash);

      db.prepare(`
        INSERT INTO user_profiles (user_id, display_name)
        VALUES (?, ?)
      `).run(userId, displayName || normalizedEmail.split('@')[0]);
    })();

    req.session.userId = userId;
    res.json({ success: true, message: 'Account created successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

router.post('/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const user = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(normalizedEmail);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    db.prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

    req.session.userId = user.id;
    res.json({ success: true, message: 'Login successful.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

router.get('/session', (req, res) => {
  if (req.session && req.session.userId) {
    const profile = db.prepare(`
      SELECT u.email, u.email_verified, u.created_at, p.display_name, p.language, p.theme
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
  req.session.destroy();
  res.clearCookie('connect.sid');
  res.json({ success: true });
});

router.delete('/account', async (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }

  try {
    // Delete cascades to all tables due to ON DELETE CASCADE
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
