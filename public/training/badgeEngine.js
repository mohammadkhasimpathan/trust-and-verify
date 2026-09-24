// badgeEngine.js
/**
 * Evaluates progress and unlocks badges deterministically.
 */
class BadgeEngine {
  constructor() {
    this.BADGES = [
      { id: 'phishing_spotter', title: 'Phishing Spotter', description: 'Passed the Phishing Knowledge Check', icon: '🎣' },
      { id: 'url_detective', title: 'URL Detective', description: 'Passed the URL Security Check', icon: '🔍' },
      { id: 'social_defender', title: 'Social Defender', description: 'Passed the Social Engineering Check', icon: '🛡️' },
      { id: 'ctf_rookie', title: 'CTF Rookie', description: 'Solved your first CTF challenge', icon: '🚩' }
    ];
  }

  async evaluateBadges() {
    if (!window.progressManager) return [];
    
    let newlyUnlocked = [];

    // Evaluate Phishing Spotter
    const phishQuiz = await window.progressManager.getQuizAttempt('quiz_phishing');
    if (phishQuiz && phishQuiz.passed) {
      if (await this._unlock('phishing_spotter')) newlyUnlocked.push('phishing_spotter');
    }

    // Evaluate URL Detective
    const urlQuiz = await window.progressManager.getQuizAttempt('quiz_urls');
    if (urlQuiz && urlQuiz.passed) {
      if (await this._unlock('url_detective')) newlyUnlocked.push('url_detective');
    }
    
    // Evaluate Social Defender
    const socialQuiz = await window.progressManager.getQuizAttempt('quiz_social_eng');
    if (socialQuiz && socialQuiz.passed) {
      if (await this._unlock('social_defender')) newlyUnlocked.push('social_defender');
    }

    // Evaluate CTF Rookie
    const ctf1 = await window.progressManager.getChallengeAttempt('ctf_01');
    if (ctf1 && ctf1.passed) {
      if (await this._unlock('ctf_rookie')) newlyUnlocked.push('ctf_rookie');
    }

    return newlyUnlocked;
  }

  async _unlock(badgeId) {
    const existingBadges = await window.progressManager.getBadges();
    const isUnlocked = existingBadges.find(b => b.id === badgeId);
    
    if (!isUnlocked) {
      await window.progressManager.unlockBadge({
        id: badgeId,
        unlockedAt: new Date().toISOString()
      });
      if (window.gamificationEngine) {
        await window.gamificationEngine.awardPoints('BADGE_UNLOCKED', badgeId, 250);
      }
      return true;
    }
    return false;
  }
}

if (typeof window !== 'undefined') window.badgeEngine = new BadgeEngine();
