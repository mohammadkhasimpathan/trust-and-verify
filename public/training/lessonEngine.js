// lessonEngine.js

class LessonEngine {
  constructor() {
    this.data = window.TrainingData || {};
  }

  getLesson(id) {
    if (!this.data.lessons) return null;
    return this.data.lessons.find(l => l.id === id);
  }

  async markCompleted(id) {
    if (!window.progressManager) return false;
    let progress = await window.progressManager.getProgress(id);
    if (!progress) {
      progress = { id, status: 'COMPLETED', completedAt: new Date().toISOString() };
      await window.progressManager.saveProgress(progress);
      
      // Gamification
      if (window.gamificationEngine) {
        await window.gamificationEngine.awardPoints('LESSON_COMPLETED', id, 50);
      }
      return true; // Newly completed
    }
    return false; // Already completed
  }
}

if (typeof window !== 'undefined') window.lessonEngine = new LessonEngine();
