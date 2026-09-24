// quizEngine.js

class QuizEngine {
  constructor() {
    this.data = window.TrainingData || {};
  }

  getQuiz(id) {
    if (!this.data.quizzes) return null;
    return this.data.quizzes.find(q => q.id === id);
  }

  evaluateAnswers(quizId, answersMap) {
    const quiz = this.getQuiz(quizId);
    if (!quiz) throw new Error('Quiz not found');

    let correctCount = 0;
    const totalCount = quiz.questions.length;
    const results = [];

    quiz.questions.forEach(q => {
      const userAnswer = answersMap[q.id];
      const isCorrect = userAnswer === q.correctAnswer;
      if (isCorrect) correctCount++;
      
      results.push({
        questionId: q.id,
        isCorrect,
        correctAnswer: q.correctAnswer,
        userAnswer,
        explanation: q.explanation
      });
    });

    const score = (correctCount / totalCount) * 100;
    const passed = score >= (quiz.passingScore || 100);

    return {
      quizId,
      score,
      passed,
      results
    };
  }

  async saveAttempt(evalResult) {
    if (!window.progressManager) return;
    
    let attemptId = 'qa_' + Math.random().toString(36).substr(2, 9);
    
    // Check previous best
    let existing = await window.progressManager.getQuizAttempt(evalResult.quizId);
    let bestScore = evalResult.score;
    let attemptCount = 1;

    if (existing) {
      attemptCount = (existing.attemptCount || 0) + 1;
      if (existing.bestScore > bestScore) {
        bestScore = existing.bestScore;
      }
    }

    const attempt = {
      id: evalResult.quizId,
      latestAttemptId: attemptId,
      latestScore: evalResult.score,
      bestScore,
      attemptCount,
      passed: evalResult.passed || (existing && existing.passed),
      timestamp: new Date().toISOString()
    };

    await window.progressManager.saveQuizAttempt(attempt);

    // Gamification
    if (window.gamificationEngine) {
      if (evalResult.passed) {
        await window.gamificationEngine.awardPoints('QUIZ_PASSED', evalResult.quizId, 100);
      }
      if (evalResult.score === 100) {
        await window.gamificationEngine.awardPoints('QUIZ_PERFECT', evalResult.quizId, 50);
      }
    }

    return attempt;
  }
}

if (typeof window !== 'undefined') window.quizEngine = new QuizEngine();
