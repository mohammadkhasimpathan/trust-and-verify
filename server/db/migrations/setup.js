const db = require('../connection');

function runMigrations() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      email_verified BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login_at DATETIME,
      status TEXT DEFAULT 'ACTIVE'
    );

    CREATE TABLE IF NOT EXISTS user_profiles (
      user_id TEXT PRIMARY KEY,
      display_name TEXT,
      avatar_reference TEXT,
      timezone TEXT,
      language TEXT DEFAULT 'en',
      theme TEXT DEFAULT 'dark',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      module TEXT NOT NULL,
      score REAL,
      severity TEXT,
      verdict TEXT,
      summary TEXT,
      indicators TEXT,
      recommendations TEXT,
      metadata TEXT,
      fingerprint TEXT,
      engine_version TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      deleted_at DATETIME,
      version INTEGER DEFAULT 1,
      device_id TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS training_progress (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      status TEXT,
      completed_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      deleted_at DATETIME,
      version INTEGER DEFAULT 1,
      device_id TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(user_id, id)
    );

    CREATE TABLE IF NOT EXISTS quiz_attempts (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      latest_attempt_id TEXT,
      latest_score REAL,
      best_score REAL,
      attempt_count INTEGER,
      passed BOOLEAN,
      timestamp DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      deleted_at DATETIME,
      version INTEGER DEFAULT 1,
      device_id TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(user_id, id)
    );

    CREATE TABLE IF NOT EXISTS challenge_attempts (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      passed BOOLEAN,
      points_earned REAL,
      hints_used TEXT,
      timestamp DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      deleted_at DATETIME,
      version INTEGER DEFAULT 1,
      device_id TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(user_id, id)
    );

    CREATE TABLE IF NOT EXISTS badges (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      unlocked_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      deleted_at DATETIME,
      version INTEGER DEFAULT 1,
      device_id TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(user_id, id)
    );

    CREATE TABLE IF NOT EXISTS certificates (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      course_id TEXT NOT NULL,
      course_title TEXT,
      learner_name TEXT,
      score REAL,
      issue_date DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      deleted_at DATETIME,
      version INTEGER DEFAULT 1,
      device_id TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(user_id, id)
    );

    CREATE TABLE IF NOT EXISTS training_events (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      event_id TEXT NOT NULL,
      event_type TEXT,
      activity_id TEXT,
      points REAL,
      details TEXT,
      timestamp DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      deleted_at DATETIME,
      version INTEGER DEFAULT 1,
      device_id TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(user_id, event_id)
    );

    CREATE TABLE IF NOT EXISTS sync_metadata (
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      last_sync_at DATETIME,
      PRIMARY KEY (user_id, device_id),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS user_sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      device_label TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS mfa_secrets (
      user_id TEXT PRIMARY KEY,
      secret_encrypted TEXT NOT NULL,
      is_enabled BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS mfa_backup_codes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      is_used BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      used_at DATETIME,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS auth_tokens (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      token_type TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      is_used BOOLEAN DEFAULT 0,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      event_type TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      ip_metadata TEXT,
      user_agent_metadata TEXT,
      success BOOLEAN,
      metadata TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS organizations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      owner_user_id TEXT NOT NULL,
      status TEXT DEFAULT 'ACTIVE',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE RESTRICT
    );

    CREATE TABLE IF NOT EXISTS organization_members (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      role TEXT NOT NULL,
      status TEXT DEFAULT 'ACTIVE',
      joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(organization_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS teams (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      created_by TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
      FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE RESTRICT
    );

    CREATE TABLE IF NOT EXISTS team_members (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(team_id) REFERENCES teams(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(team_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS organization_invitations (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL,
      email TEXT NOT NULL,
      role TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      invited_by TEXT NOT NULL,
      expires_at DATETIME NOT NULL,
      accepted_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
      FOREIGN KEY(invited_by) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS organization_events (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL,
      actor_user_id TEXT,
      event_type TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      metadata TEXT,
      FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
      FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL
    );


  `);
}

module.exports = { runMigrations };
