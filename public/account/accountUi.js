// accountUi.js

class AccountUi {
  constructor() {
    this.state = {
      mode: 'login' // 'login' or 'register'
    };
    this.refreshAuth();
  }

  async refreshAuth() {
    if (!window.syncEngine) return;
    const auth = await window.syncEngine.checkAuthStatus();
    this.renderState(auth);
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
      document.getElementById('account-last-sync').textContent = new Date().toLocaleString();
    } else {
      guestUi.style.display = 'block';
      userUi.style.display = 'none';
    }
  }

  showLogin() {
    this.state.mode = 'login';
    document.getElementById('auth-modal').style.display = 'flex';
    document.getElementById('auth-title').textContent = 'Sign In';
    document.getElementById('auth-name-group').style.display = 'none';
    document.getElementById('auth-submit-btn').textContent = 'Sign In';
    document.getElementById('auth-error').style.display = 'none';
  }

  showRegister() {
    this.state.mode = 'register';
    document.getElementById('auth-modal').style.display = 'flex';
    document.getElementById('auth-title').textContent = 'Create Account';
    document.getElementById('auth-name-group').style.display = 'block';
    document.getElementById('auth-submit-btn').textContent = 'Create Account';
    document.getElementById('auth-error').style.display = 'none';
  }

  closeAuthModal() {
    document.getElementById('auth-modal').style.display = 'none';
    document.getElementById('auth-form').reset();
  }

  async submitAuth() {
    const email = document.getElementById('auth-email').value;
    const password = document.getElementById('auth-password').value;
    const displayName = document.getElementById('auth-name').value;
    const errEl = document.getElementById('auth-error');
    
    errEl.style.display = 'none';
    
    try {
      if (this.state.mode === 'login') {
        await window.syncEngine.login(email, password);
        if (window.addLogLine) window.addLogLine('[AUTH] Login successful.', 'success');
      } else {
        await window.syncEngine.register(email, password, displayName);
        if (window.addLogLine) window.addLogLine('[AUTH] Account created successfully.', 'success');
      }
      this.closeAuthModal();
      this.refreshAuth();
      
      // Initial sync on login
      setTimeout(() => this.syncNow(), 1000);
      
    } catch (e) {
      errEl.textContent = e.message;
      errEl.style.display = 'block';
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
