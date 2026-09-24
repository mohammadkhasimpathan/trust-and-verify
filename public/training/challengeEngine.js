// challengeEngine.js

class ChallengeEngine {
  constructor() {
    this.data = window.TrainingData || {};
  }

  getChallenge(id) {
    if (!this.data.challenges) return null;
    return this.data.challenges.find(c => c.id === id);
  }

  async submitAnswer(challengeId, answerIndex) {
    const chal = this.getChallenge(challengeId);
    if (!chal) throw new Error('Challenge not found');

    const isCorrect = answerIndex === chal.correctAnswer;
    
    if (isCorrect && window.progressManager) {
      let existing = await window.progressManager.getChallengeAttempt(challengeId);
      if (!existing || !existing.passed) {
        await window.progressManager.saveChallengeAttempt({
          id: challengeId,
          passed: true,
          timestamp: new Date().toISOString()
        });
        
        if (window.gamificationEngine) {
          await window.gamificationEngine.awardPoints('CHALLENGE_COMPLETED', challengeId, chal.reward || 100);
        }
      }
    }

    return {
      isCorrect,
      explanation: chal.explanation
    };
  }
}

if (typeof window !== 'undefined') window.challengeEngine = new ChallengeEngine();
