const test = require('node:test');
const assert = require('node:assert');

// Mock browser environment for Phase 6 files
global.window = {};
global.TrainingData = undefined; // Will be set by trainingData.js

const TrainingData = require('../public/training/trainingData.js');

test('Phase 6: Training Data Engine', async (t) => {
  await t.test('Training data is structured correctly', () => {
    assert.ok(TrainingData.courses);
    assert.ok(TrainingData.lessons);
    assert.ok(TrainingData.quizzes);
    assert.ok(TrainingData.challenges);
    assert.ok(TrainingData.ctf);
  });
});

test('Phase 6: Quiz Logic (quizEngine)', async (t) => {
  // Mock window.progressManager
  global.window = {
    TrainingData: TrainingData,
    progressManager: {
      getQuizAttempt: async () => null,
      saveQuizAttempt: async () => {},
      logEvent: async () => {}
    },
    gamificationEngine: {
      awardPoints: async () => {}
    }
  };

  require('../public/training/quizEngine.js');
  const quizEngine = global.window.quizEngine;

  await t.test('evaluates correct answers properly', () => {
    const quizId = 'quiz_phishing';
    const answersMap = {
      q1: 1, // correct
      q2: 3  // correct
    };
    
    const result = quizEngine.evaluateAnswers(quizId, answersMap);
    assert.strictEqual(result.score, 100);
    assert.strictEqual(result.passed, true);
  });

  await t.test('evaluates incorrect answers properly', () => {
    const quizId = 'quiz_phishing';
    const answersMap = {
      q1: 0, // incorrect
      q2: 3  // correct
    };
    
    const result = quizEngine.evaluateAnswers(quizId, answersMap);
    assert.strictEqual(result.score, 50);
    assert.strictEqual(result.passed, false); // passing is 100 for this quiz
  });
});

test('Phase 6: CTF Validation', async (t) => {
  global.window.TrainingData = TrainingData;
  require('../public/training/ctfEngine.js');
  const ctfEngine = global.window.ctfEngine;

  await t.test('validates correct flag', async () => {
    const ctfId = 'ctf_01';
    // override submitFlag dependencies to just test logic
    const ctf = ctfEngine.getCtf(ctfId);
    const isValid = ctf.validateLocal('TV{url_encoding_is_fun}');
    assert.strictEqual(isValid, true);
  });

  await t.test('rejects incorrect flag', async () => {
    const ctfId = 'ctf_01';
    const ctf = ctfEngine.getCtf(ctfId);
    const isValid = ctf.validateLocal('TV{wrong_flag}');
    assert.strictEqual(isValid, false);
  });
});
