const express = require('express');
const { requireAuth } = require('../auth/authMiddleware');
const db = require('../db/connection');

const router = express.Router();

router.use(requireAuth);

router.post('/push', express.json({ limit: '5mb' }), (req, res) => {
  const { queue, deviceId } = req.body;
  if (!queue || !Array.isArray(queue) || !deviceId) {
    return res.status(400).json({ error: 'Invalid sync payload.' });
  }
  
  if (queue.length > 500) {
    return res.status(400).json({ error: 'Payload too large. Max 500 records per push.' });
  }

  const userId = req.session.userId;
  
  try {
    const results = [];
    
    db.transaction(() => {
      for (const op of queue) {
        if (!op.entityType || !op.entityId || !op.operation) continue;
        
        const timestamp = op.updatedAt || new Date().toISOString();
        const payloadStr = op.payload ? JSON.stringify(op.payload) : null;
        
        if (op.entityType === 'scans') {
          if (op.operation === 'CREATE' || op.operation === 'UPDATE') {
            const p = op.payload;
            db.prepare(`
              INSERT INTO scans (id, user_id, module, score, severity, verdict, summary, indicators, recommendations, metadata, fingerprint, engine_version, created_at, updated_at, device_id)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(id) DO UPDATE SET
                updated_at = excluded.updated_at,
                device_id = excluded.device_id
            `).run(
              op.entityId, userId, p.module || '', p.score || 0, p.severity || '', p.verdict || '', 
              p.summary || '', p.indicators ? JSON.stringify(p.indicators) : '[]', 
              p.recommendations ? JSON.stringify(p.recommendations) : '[]', 
              p.metadata ? JSON.stringify(p.metadata) : '{}', 
              p.fingerprint || '', p.engineVersion || '', 
              p.timestamp || timestamp, timestamp, deviceId
            );
          } else if (op.operation === 'DELETE') {
            db.prepare('DELETE FROM scans WHERE id = ? AND user_id = ?').run(op.entityId, userId);
          }
        }
        else if (op.entityType === 'trainingProgress') {
          if (op.operation === 'CREATE' || op.operation === 'UPDATE') {
            const p = op.payload;
            db.prepare(`
              INSERT INTO training_progress (id, user_id, status, completed_at, updated_at, device_id)
              VALUES (?, ?, ?, ?, ?, ?)
              ON CONFLICT(id) DO UPDATE SET
                status = excluded.status, completed_at = excluded.completed_at, updated_at = excluded.updated_at
            `).run(op.entityId, userId, p.status, p.completedAt, timestamp, deviceId);
          }
        }
        else if (op.entityType === 'quizAttempts') {
          if (op.operation === 'CREATE' || op.operation === 'UPDATE') {
            const p = op.payload;
            db.prepare(`
              INSERT INTO quiz_attempts (id, user_id, latest_attempt_id, latest_score, best_score, attempt_count, passed, timestamp, updated_at, device_id)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(id) DO UPDATE SET
                best_score = MAX(quiz_attempts.best_score, excluded.best_score),
                passed = quiz_attempts.passed OR excluded.passed,
                updated_at = excluded.updated_at
            `).run(op.entityId, userId, p.latestAttemptId, p.latestScore, p.bestScore, p.attemptCount, p.passed ? 1 : 0, p.timestamp, timestamp, deviceId);
          }
        }
        else if (op.entityType === 'challengeAttempts') {
          if (op.operation === 'CREATE' || op.operation === 'UPDATE') {
            const p = op.payload;
            db.prepare(`
              INSERT INTO challenge_attempts (id, user_id, passed, points_earned, hints_used, timestamp, updated_at, device_id)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(id) DO UPDATE SET
                passed = challenge_attempts.passed OR excluded.passed,
                hints_used = excluded.hints_used,
                updated_at = excluded.updated_at
            `).run(op.entityId, userId, p.passed ? 1 : 0, p.pointsEarned, p.hintsUsed ? JSON.stringify(p.hintsUsed) : '[]', p.timestamp, timestamp, deviceId);
          }
        }
        else if (op.entityType === 'badges') {
          if (op.operation === 'CREATE' || op.operation === 'UPDATE') {
            const p = op.payload;
            db.prepare(`
              INSERT OR IGNORE INTO badges (id, user_id, unlocked_at, updated_at, device_id)
              VALUES (?, ?, ?, ?, ?)
            `).run(op.entityId, userId, p.unlockedAt, timestamp, deviceId);
          }
        }
        else if (op.entityType === 'certificates') {
          if (op.operation === 'CREATE' || op.operation === 'UPDATE') {
            const p = op.payload;
            db.prepare(`
              INSERT OR IGNORE INTO certificates (id, user_id, course_id, course_title, learner_name, score, issue_date, updated_at, device_id)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(op.entityId, userId, p.courseId, p.courseTitle, p.learnerName, p.score, p.issueDate, timestamp, deviceId);
          }
        }
        else if (op.entityType === 'trainingEvents') {
          if (op.operation === 'CREATE') {
            const p = op.payload;
            db.prepare(`
              INSERT OR IGNORE INTO training_events (id, user_id, event_id, event_type, activity_id, points, details, timestamp, updated_at, device_id)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(op.entityId, userId, p.eventId, p.eventType, p.activityId, p.points, p.details ? JSON.stringify(p.details) : '{}', p.timestamp, timestamp, deviceId);
          }
        }
        
        results.push({ id: op.id, status: 'success' });
      }

      db.prepare(`
        INSERT INTO sync_metadata (user_id, device_id, last_sync_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id, device_id) DO UPDATE SET
          last_sync_at = CURRENT_TIMESTAMP
      `).run(userId, deviceId);

    })();

    res.json({ success: true, processed: results });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Sync push failed.' });
  }
});

router.post('/pull', (req, res) => {
  const { deviceId, lastSyncAt } = req.body;
  const userId = req.session.userId;
  
  if (!deviceId) return res.status(400).json({ error: 'deviceId required.' });

  try {
    // Only pull items updated after lastSyncAt, or all if null
    let queryTail = 'WHERE user_id = ?';
    const params = [userId];
    
    if (lastSyncAt) {
      queryTail += ' AND updated_at > ?';
      params.push(lastSyncAt);
    }
    
    const scans = db.prepare(`SELECT * FROM scans ${queryTail}`).all(...params);
    const trainingProgress = db.prepare(`SELECT * FROM training_progress ${queryTail}`).all(...params);
    const quizAttempts = db.prepare(`SELECT * FROM quiz_attempts ${queryTail}`).all(...params);
    const challengeAttempts = db.prepare(`SELECT * FROM challenge_attempts ${queryTail}`).all(...params);
    const badges = db.prepare(`SELECT * FROM badges ${queryTail}`).all(...params);
    const certificates = db.prepare(`SELECT * FROM certificates ${queryTail}`).all(...params);
    const trainingEvents = db.prepare(`SELECT * FROM training_events ${queryTail}`).all(...params);

    const data = {
      scans,
      trainingProgress,
      quizAttempts,
      challengeAttempts,
      badges,
      certificates,
      trainingEvents,
      serverTime: new Date().toISOString()
    };
    
    res.json({ success: true, data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Sync pull failed.' });
  }
});

router.get('/export', (req, res) => {
  const userId = req.session.userId;
  try {
    const profile = db.prepare('SELECT display_name, language, theme, created_at FROM user_profiles WHERE user_id = ?').get(userId);
    const scans = db.prepare('SELECT * FROM scans WHERE user_id = ?').all(userId);
    const trainingProgress = db.prepare('SELECT * FROM training_progress WHERE user_id = ?').all(userId);
    const quizAttempts = db.prepare('SELECT * FROM quiz_attempts WHERE user_id = ?').all(userId);
    const challengeAttempts = db.prepare('SELECT * FROM challenge_attempts WHERE user_id = ?').all(userId);
    const badges = db.prepare('SELECT * FROM badges WHERE user_id = ?').all(userId);
    const certificates = db.prepare('SELECT * FROM certificates WHERE user_id = ?').all(userId);
    const trainingEvents = db.prepare('SELECT * FROM training_events WHERE user_id = ?').all(userId);

    const exportData = {
      version: '1.0',
      exportDate: new Date().toISOString(),
      profile,
      scans,
      trainingProgress,
      quizAttempts,
      challengeAttempts,
      badges,
      certificates,
      trainingEvents
    };

    res.json(exportData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Export failed.' });
  }
});

module.exports = router;
