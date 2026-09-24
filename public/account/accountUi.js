// accountUi.js

class AccountUi {
  constructor() {
    this.state = {
      mode: 'login', // login, register, forgot, reset, change-password, mfa-disable, mfa-verify
      resetToken: null
    };
    this.refreshAuth();
  }

  async refreshAuth() {
    if (!window.syncEngine) return;
    const auth = await window.syncEngine.checkAuthStatus();
    this.renderState(auth);
    if (auth.authenticated) {
      this.loadSessions();
      this.loadSecurityEvents();
    }
  }

  renderState(auth) {
    const guestUi = document.getElementById('account-guest-ui');
    const userUi = document.getElementById('account-user-ui');
    if (!guestUi || !userUi) return;

    if (auth.authenticated) {
      guestUi.style.display = 'none';
      userUi.style.display = 'block';
      
      document.getElementById('account-name').textContent = auth.user.displayName;
      document.getElementById('account-email').textContent = auth.user.email;
      
      const vBadge = document.getElementById('account-verified-badge');
      const uBadge = document.getElementById('account-unverified-badge');
      if (auth.user.email_verified) {
        vBadge.style.display = 'inline';
        uBadge.style.display = 'none';
      } else {
        vBadge.style.display = 'none';
        uBadge.style.display = 'inline';
      }

      document.getElementById('account-mfa-status').textContent = auth.user.mfa_enabled ? 'Enabled' : 'Disabled';
      document.getElementById('account-mfa-status').style.color = auth.user.mfa_enabled ? '#00ff66' : '#aaa';
      
      document.getElementById('btn-setup-mfa').style.display = auth.user.mfa_enabled ? 'none' : 'block';
      document.getElementById('btn-disable-mfa').style.display = auth.user.mfa_enabled ? 'block' : 'none';
      
    } else {
      guestUi.style.display = 'block';
      userUi.style.display = 'none';
    }
  }

  _hideAllGroups() {
    ['auth-name-group', 'auth-email-group', 'auth-password-group', 'auth-new-password-group', 'auth-totp-group', 'auth-links'].forEach(id => {
      document.getElementById(id).style.display = 'none';
    });
    document.getElementById('auth-password-label').textContent = 'Password';
    document.getElementById('auth-error').style.display = 'none';
  }

  showLogin() {
    this.state.mode = 'login';
    document.getElementById('auth-modal').style.display = 'flex';
    document.getElementById('auth-title').textContent = 'Sign In';
    this._hideAllGroups();
    
    document.getElementById('auth-email-group').style.display = 'block';
    document.getElementById('auth-password-group').style.display = 'block';
    document.getElementById('auth-links').style.display = 'block';
    document.getElementById('auth-submit-btn').textContent = 'Sign In';
  }

  showRegister() {
    this.state.mode = 'register';
    document.getElementById('auth-modal').style.display = 'flex';
    document.getElementById('auth-title').textContent = 'Create Account';
    this._hideAllGroups();
    
    document.getElementById('auth-name-group').style.display = 'block';
    document.getElementById('auth-email-group').style.display = 'block';
    document.getElementById('auth-password-group').style.display = 'block';
    document.getElementById('auth-submit-btn').textContent = 'Create Account';
  }
  
  showForgotPassword() {
    this.state.mode = 'forgot';
    document.getElementById('auth-title').textContent = 'Forgot Password';
    this._hideAllGroups();
    
    document.getElementById('auth-email-group').style.display = 'block';
    document.getElementById('auth-submit-btn').textContent = 'Send Reset Link';
  }

  showResetPassword(token) {
    this.state.mode = 'reset';
    this.state.resetToken = token;
    document.getElementById('auth-modal').style.display = 'flex';
    document.getElementById('auth-title').textContent = 'Reset Password';
    this._hideAllGroups();
    
    document.getElementById('auth-new-password-group').style.display = 'block';
    document.getElementById('auth-submit-btn').textContent = 'Reset Password';
  }

  showChangePassword() {
    this.state.mode = 'change-password';
    document.getElementById('auth-modal').style.display = 'flex';
    document.getElementById('auth-title').textContent = 'Change Password';
    this._hideAllGroups();
    
    document.getElementById('auth-password-group').style.display = 'block';
    document.getElementById('auth-password-label').textContent = 'Current Password';
    document.getElementById('auth-new-password-group').style.display = 'block';
    document.getElementById('auth-submit-btn').textContent = 'Change Password';
  }

  showMfaDisable() {
    this.state.mode = 'mfa-disable';
    document.getElementById('auth-modal').style.display = 'flex';
    document.getElementById('auth-title').textContent = 'Disable MFA';
    this._hideAllGroups();
    
    document.getElementById('auth-password-group').style.display = 'block';
    document.getElementById('auth-totp-group').style.display = 'block';
    document.getElementById('auth-submit-btn').textContent = 'Disable MFA';
  }

  closeAuthModal() {
    document.getElementById('auth-modal').style.display = 'none';
    document.getElementById('auth-form').reset();
  }

  async submitAuth() {
    const email = document.getElementById('auth-email').value;
    const password = document.getElementById('auth-password').value;
    const newPassword = document.getElementById('auth-new-password').value;
    const displayName = document.getElementById('auth-name').value;
    const totp = document.getElementById('auth-totp').value;
    const errEl = document.getElementById('auth-error');
    
    errEl.style.display = 'none';
    
    try {
      if (this.state.mode === 'login') {
        try {
          await window.syncEngine.login(email, password, totp);
          if (window.addLogLine) window.addLogLine('[AUTH] Login successful.', 'success');
          this.closeAuthModal();
          this.refreshAuth();
        } catch (e) {
          if (e.message === 'MFA_REQUIRED') {
            document.getElementById('auth-totp-group').style.display = 'block';
            errEl.textContent = 'MFA code is required.';
            errEl.style.display = 'block';
            return;
          }
          throw e;
        }
      } 
      else if (this.state.mode === 'register') {
        const res = await window.syncEngine.register(email, password, displayName);
        alert(res.message);
        this.showLogin();
      }
      else if (this.state.mode === 'forgot') {
        const res = await window.syncEngine.forgotPassword(email);
        alert(res.message);
        this.closeAuthModal();
      }
      else if (this.state.mode === 'reset') {
        const res = await window.syncEngine.resetPassword(this.state.resetToken, newPassword);
        alert(res.message);
        this.closeAuthModal();
        this.showLogin();
      }
      else if (this.state.mode === 'change-password') {
        const res = await window.syncEngine.changePassword(password, newPassword);
        alert(res.message);
        this.closeAuthModal();
      }
      else if (this.state.mode === 'mfa-disable') {
        const res = await window.syncEngine.mfaDisable(password, totp);
        alert(res.message);
        this.closeAuthModal();
        this.refreshAuth();
      }
    } catch (e) {
      errEl.textContent = e.message;
      errEl.style.display = 'block';
    }
  }

  async verifyEmailToken(token) {
    try {
      const res = await window.syncEngine.verifyEmailToken(token);
      alert(res.message);
      this.refreshAuth();
    } catch (err) {
      alert(err.message);
    }
  }

  async showMfaSetup() {
    try {
      const data = await window.syncEngine.mfaSetup();
      document.getElementById('mfa-secret-text').textContent = data.secret;
      
      // Load qrcode dynamically if needed or just display uri
      if (typeof QRCode !== 'undefined') {
        QRCode.toCanvas(document.getElementById('mfa-qr-canvas'), data.otpauth, {
          width: 200,
          margin: 1,
          color: { dark: '#000000', light: '#ffffff' }
        });
      } else {
        // Fallback or dynamically load
        const s = document.createElement('script');
        s.src = 'https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js';
        s.onload = () => {
          QRCode.toCanvas(document.getElementById('mfa-qr-canvas'), data.otpauth, {
            width: 200, margin: 1
          });
        };
        document.head.appendChild(s);
      }
      
      document.getElementById('mfa-modal').style.display = 'flex';
      document.getElementById('mfa-verify-code').value = '';
      document.getElementById('mfa-error').style.display = 'none';
    } catch (err) {
      alert(err.message);
    }
  }
  
  closeMfaModal() {
    document.getElementById('mfa-modal').style.display = 'none';
  }

  async submitMfaVerify() {
    const code = document.getElementById('mfa-verify-code').value;
    const errEl = document.getElementById('mfa-error');
    errEl.style.display = 'none';
    
    try {
      const data = await window.syncEngine.mfaVerify(code);
      this.closeMfaModal();
      this.refreshAuth();
      
      // Show backup codes
      const list = document.getElementById('backup-codes-list');
      list.innerHTML = data.backupCodes.join('<br>');
      document.getElementById('backup-codes-modal').style.display = 'flex';
      
    } catch (err) {
      errEl.textContent = err.message;
      errEl.style.display = 'block';
    }
  }

  async loadSessions() {
    try {
      const sessions = await window.syncEngine.getSessions();
      const list = document.getElementById('account-sessions-list');
      list.innerHTML = '';
      sessions.forEach(s => {
        const div = document.createElement('div');
        div.style.padding = '8px';
        div.style.borderBottom = '1px solid rgba(255,255,255,0.1)';
        div.style.display = 'flex';
        div.style.justifyContent = 'space-between';
        
        let html = `<div>
          <div><strong>${s.deviceLabel || 'Unknown'}</strong> ${s.current ? '<span style="color:#00ff66">[Current]</span>' : ''}</div>
          <div style="color: #888;">Active: ${new Date(s.lastSeenAt).toLocaleString()}</div>
        </div>`;
        
        if (!s.current) {
          html += `<button class="action-btn secondary-action" style="padding: 2px 8px;" onclick="window.accountUi.revokeSession('${s.id}')">Revoke</button>`;
        }
        
        div.innerHTML = html;
        list.appendChild(div);
      });
    } catch (e) {
      console.warn('Failed to load sessions', e);
    }
  }
  
  async revokeSession(id) {
    if (confirm('Revoke this session?')) {
      try {
        await window.syncEngine.revokeSession(id);
        this.loadSessions();
      } catch(e) {
        alert(e.message);
      }
    }
  }

  async revokeOtherSessions() {
    if (confirm('Revoke all other active sessions?')) {
      try {
        await window.syncEngine.revokeOtherSessions();
        this.loadSessions();
      } catch(e) {
        alert(e.message);
      }
    }
  }

  async loadSecurityEvents() {
    try {
      const events = await window.syncEngine.getSecurityEvents();
      const list = document.getElementById('account-events-list');
      list.innerHTML = '';
      events.forEach(e => {
        const div = document.createElement('div');
        div.style.padding = '8px';
        div.style.borderBottom = '1px solid rgba(255,255,255,0.1)';
        
        const color = e.success ? '#00ff66' : '#ff003c';
        
        div.innerHTML = `
          <div><strong style="color: ${color};">${e.event_type}</strong></div>
          <div style="color: #888;">${new Date(e.created_at).toLocaleString()} - ${e.ip_metadata || 'Unknown IP'}</div>
        `;
        list.appendChild(div);
      });
    } catch (e) {
      console.warn('Failed to load security events', e);
    }
  }

  async logout() {
    await window.syncEngine.logout();
    if (window.addLogLine) window.addLogLine('[AUTH] Logged out.', 'system');
    this.refreshAuth();
  }

  async deleteAccount() {
    if (confirm("This permanently deletes your cloud account and synchronized cloud data. Local browser data may remain unless you choose to remove it. Continue?")) {
      try {
        await window.syncEngine.deleteAccount();
        if (window.addLogLine) window.addLogLine('[AUTH] Account deleted.', 'system');
        this.refreshAuth();
      } catch (e) {
        alert(e.message);
      }
    }
  }

  async syncNow() {
    await window.syncEngine.syncNow();
    document.getElementById('account-last-sync').textContent = new Date().toLocaleString();
  }
  
  async exportData() {
    try {
      const res = await fetch('/api/sync/export');
      if (!res.ok) throw new Error('Export failed.');
      const data = await res.json();
      
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'trust-verify-cloud-export.json';
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(err.message);
    }
  }
}

if (typeof window !== 'undefined') window.accountUi = new AccountUi();
