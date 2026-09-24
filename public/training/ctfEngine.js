// ctfEngine.js

class CtfEngine {
  constructor() {
    this.data = window.TrainingData || {};
  }

  getCtf(id) {
    if (!this.data.ctf) return null;
    return this.data.ctf.find(c => c.id === id);
  }

  async submitFlag(ctfId, flag) {
    const ctf = this.getCtf(ctfId);
    if (!ctf) throw new Error('CTF not found');

    const isValid = ctf.validateLocal(flag);
    
    if (isValid && window.progressManager) {
      let existing = await window.progressManager.getChallengeAttempt(ctfId);
      
      // Determine points (subtract hints if any)
      let points = ctf.reward || 150;
      if (existing && existing.hintsUsed) {
        existing.hintsUsed.forEach(hId => {
          const hintDef = ctf.hints.find(h => h.id === hId);
          if (hintDef) points -= (hintDef.penalty || 0);
        });
      }
      points = Math.max(0, points);

      if (!existing || !existing.passed) {
        await window.progressManager.saveChallengeAttempt({
          id: ctfId,
          passed: true,
          pointsEarned: points,
          hintsUsed: existing ? existing.hintsUsed : [],
          timestamp: new Date().toISOString()
        });
        
        if (window.gamificationEngine) {
          await window.gamificationEngine.awardPoints('CTF_SOLVED', ctfId, points);
        }
      }
    }

    return {
      isValid
    };
  }

  async useHint(ctfId, hintId) {
    const ctf = this.getCtf(ctfId);
    if (!ctf) throw new Error('CTF not found');

    const hint = ctf.hints.find(h => h.id === hintId);
    if (!hint) return null;

    if (window.progressManager) {
      let existing = await window.progressManager.getChallengeAttempt(ctfId);
      if (!existing) {
        existing = { id: ctfId, passed: false, hintsUsed: [] };
      }
      if (!existing.hintsUsed) existing.hintsUsed = [];
      if (!existing.hintsUsed.includes(hintId)) {
        existing.hintsUsed.push(hintId);
        await window.progressManager.saveChallengeAttempt(existing);
      }
    }

    return hint.text;
  }
}

if (typeof window !== 'undefined') window.ctfEngine = new CtfEngine();
