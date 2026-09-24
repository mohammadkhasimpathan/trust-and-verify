// gamificationEngine.js
/**
 * Gamification Engine for Trust & Verify Phase 6.
 * Computes XP, levels, and streaks deterministically from the local progress manager.
 */

class GamificationEngine {
  constructor() {
    this.LEVEL_THRESHOLDS = [
      { level: 1, name: 'Beginner', xp: 0 },
      { level: 2, name: 'Aware', xp: 200 },
      { level: 3, name: 'Defender', xp: 500 },
      { level: 4, name: 'Analyst', xp: 1000 },
      { level: 5, name: 'Security Champion', xp: 2000 }
    ];
  }

  calculateLevel(totalXp) {
    let currentLevel = this.LEVEL_THRESHOLDS[0];
    for (let i = 0; i < this.LEVEL_THRESHOLDS.length; i++) {
      if (totalXp >= this.LEVEL_THRESHOLDS[i].xp) {
        currentLevel = this.LEVEL_THRESHOLDS[i];
      } else {
        break;
      }
    }
    return currentLevel;
  }

  async getTotalXp() {
    if (!window.progressManager) return 0;
    const events = await window.progressManager.getEvents();
    return events.reduce((sum, ev) => sum + (ev.points || 0), 0);
  }

  async getCurrentStreak() {
    if (!window.progressManager) return 0;
    const events = await window.progressManager.getEvents();
    if (!events.length) return 0;

    // Filter events that count towards streak (e.g., completions)
    const validEvents = events.filter(e => 
      ['LESSON_COMPLETED', 'QUIZ_PASSED', 'CHALLENGE_COMPLETED', 'CTF_SOLVED'].includes(e.eventType)
    );

    if (!validEvents.length) return 0;

    // Sort descending by date
    validEvents.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    let streak = 0;
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    let currentDateToCheck = today;
    
    // Check if the most recent event was today or yesterday
    const latestEventDate = new Date(validEvents[0].timestamp);
    latestEventDate.setHours(0,0,0,0);
    
    const diffTime = Math.abs(today - latestEventDate);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 
    
    if (diffDays > 1) {
      return 0; // Streak broken
    }

    let dateMap = {};
    validEvents.forEach(ev => {
      const d = new Date(ev.timestamp);
      d.setHours(0,0,0,0);
      dateMap[d.toISOString()] = true;
    });

    // Count backwards from latestEventDate
    let checkDate = new Date(latestEventDate);
    while (dateMap[checkDate.toISOString()]) {
      streak++;
      checkDate.setDate(checkDate.getDate() - 1);
    }

    return streak;
  }

  async awardPoints(eventType, activityId, points, details = {}) {
    if (!window.progressManager) return null;
    
    // Prevent duplicate rewards for the same activity and event type
    const existingEvents = await window.progressManager.getEvents();
    const alreadyRewarded = existingEvents.find(e => e.eventType === eventType && e.activityId === activityId);
    
    if (alreadyRewarded && !details.allowDuplicate) {
      console.log(`Points already awarded for ${eventType} on ${activityId}`);
      return null;
    }

    return await window.progressManager.logEvent(eventType, activityId, points, details);
  }
}

if (typeof window !== 'undefined') window.gamificationEngine = new GamificationEngine();
