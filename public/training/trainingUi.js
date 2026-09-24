// trainingUi.js

class TrainingUi {
  constructor() {
    this.container = document.getElementById('training-content-area');
  }

  async renderDashboard() {
    if (!this.container) return;
    
    await this.updateTopBar();
    
    // Check for badge unlocks
    if (window.badgeEngine) {
      const unlocked = await window.badgeEngine.evaluateBadges();
      unlocked.forEach(bId => {
        if (window.addLogLine) addLogLine(`[GAMIFICATION] Unlocked badge: ${bId}!`, 'success');
      });
    }

    let html = `
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
        
        <div class="glass-panel" style="padding: 20px; border: 1px solid rgba(0, 240, 255, 0.2);">
          <h3 style="color: #00f0ff; margin-top: 0;">📚 Lessons</h3>
          <p style="font-size: 12px; color: #aaa; margin-bottom: 15px;">Learn security concepts.</p>
          <div id="ui-lessons-list" style="display: flex; flex-direction: column; gap: 10px;"></div>
        </div>

        <div class="glass-panel" style="padding: 20px; border: 1px solid rgba(0, 240, 255, 0.2);">
          <h3 style="color: #ffaa00; margin-top: 0;">📝 Quizzes</h3>
          <p style="font-size: 12px; color: #aaa; margin-bottom: 15px;">Test your knowledge.</p>
          <div id="ui-quizzes-list" style="display: flex; flex-direction: column; gap: 10px;"></div>
        </div>

        <div class="glass-panel" style="padding: 20px; border: 1px solid rgba(0, 240, 255, 0.2);">
          <h3 style="color: #ff003c; margin-top: 0;">🎯 Challenges & CTF</h3>
          <p style="font-size: 12px; color: #aaa; margin-bottom: 15px;">Apply skills practically.</p>
          <div id="ui-chal-list" style="display: flex; flex-direction: column; gap: 10px;"></div>
        </div>

        <div class="glass-panel" style="padding: 20px; border: 1px solid rgba(0, 240, 255, 0.2);">
          <h3 style="color: #00ff66; margin-top: 0;">🏅 Badges & Certs</h3>
          <p style="font-size: 12px; color: #aaa; margin-bottom: 15px;">Your achievements.</p>
          <div id="ui-badges-list" style="display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px;"></div>
          <button class="action-btn" onclick="window.trainingUi.checkAndRenderCertificate('course_fundamentals')">Generate Fundamentals Cert</button>
          
          <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.1); margin: 20px 0;">
          <button class="action-btn" style="background: rgba(255,0,0,0.1); border-color: rgba(255,0,0,0.3); color: #ff5555;" onclick="window.trainingUi.resetProgress()">Reset Progress</button>
        </div>

      </div>
    `;

    this.container.innerHTML = html;

    await this.populateLessons();
    await this.populateQuizzes();
    await this.populateChallenges();
    await this.populateBadges();
  }

  async updateTopBar() {
    if (!window.gamificationEngine) return;
    const xp = await window.gamificationEngine.getTotalXp();
    const level = window.gamificationEngine.calculateLevel(xp);
    const streak = await window.gamificationEngine.getCurrentStreak();
    
    const elLevel = document.getElementById('train-level');
    const elXp = document.getElementById('train-xp');
    const elStreak = document.getElementById('train-streak');
    
    if (elLevel) elLevel.textContent = `Level ${level.level} — ${level.name}`;
    if (elXp) elXp.textContent = xp;
    if (elStreak) elStreak.textContent = `${streak} Days`;
  }

  async populateLessons() {
    const list = document.getElementById('ui-lessons-list');
    if (!list || !window.TrainingData) return;
    
    let html = '';
    for (const l of window.TrainingData.lessons) {
      let progress = null;
      if (window.progressManager) progress = await window.progressManager.getProgress(l.id);
      
      const isDone = progress && progress.status === 'COMPLETED';
      
      html += `
        <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.1); padding: 10px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center;">
          <div>
            <div style="font-size: 14px; font-weight: bold; color: #fff;">${l.title}</div>
            <div style="font-size: 11px; color: #aaa;">${l.difficulty} • ${l.estimatedMinutes}m</div>
          </div>
          <button class="action-btn" style="padding: 5px 10px; font-size: 12px; ${isDone ? 'border-color: #00ff66; color: #00ff66;' : ''}" onclick="window.trainingUi.renderLesson('${l.id}')">
            ${isDone ? 'Review' : 'Start'}
          </button>
        </div>
      `;
    }
    list.innerHTML = html;
  }

  async populateQuizzes() {
    const list = document.getElementById('ui-quizzes-list');
    if (!list || !window.TrainingData) return;
    
    let html = '';
    for (const q of window.TrainingData.quizzes) {
      let attempt = null;
      if (window.progressManager) attempt = await window.progressManager.getQuizAttempt(q.id);
      
      const isDone = attempt && attempt.passed;
      
      html += `
        <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.1); padding: 10px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center;">
          <div>
            <div style="font-size: 14px; font-weight: bold; color: #fff;">${q.title}</div>
            <div style="font-size: 11px; color: #aaa;">${attempt ? 'Best: ' + Math.round(attempt.bestScore) + '%' : 'Not attempted'}</div>
          </div>
          <button class="action-btn" style="padding: 5px 10px; font-size: 12px; ${isDone ? 'border-color: #ffaa00; color: #ffaa00;' : ''}" onclick="window.trainingUi.renderQuiz('${q.id}')">
            ${isDone ? 'Retake' : 'Start'}
          </button>
        </div>
      `;
    }
    list.innerHTML = html;
  }

  async populateChallenges() {
    const list = document.getElementById('ui-chal-list');
    if (!list || !window.TrainingData) return;
    
    let html = '';
    const items = [...(window.TrainingData.challenges || []), ...(window.TrainingData.ctf || [])];
    
    for (const c of items) {
      let attempt = null;
      if (window.progressManager) attempt = await window.progressManager.getChallengeAttempt(c.id);
      
      const isDone = attempt && attempt.passed;
      
      html += `
        <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.1); padding: 10px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center;">
          <div>
            <div style="font-size: 14px; font-weight: bold; color: #fff;">${c.title}</div>
            <div style="font-size: 11px; color: #aaa;">${c.category || 'CTF'} • ${c.difficulty}</div>
          </div>
          <button class="action-btn" style="padding: 5px 10px; font-size: 12px; ${isDone ? 'border-color: #ff003c; color: #ff003c;' : ''}" onclick="window.trainingUi.renderChallenge('${c.id}')">
            ${isDone ? 'Review' : 'Solve'}
          </button>
        </div>
      `;
    }
    list.innerHTML = html;
  }

  async populateBadges() {
    const list = document.getElementById('ui-badges-list');
    if (!list) return;
    
    let unlocked = [];
    if (window.progressManager) unlocked = await window.progressManager.getBadges();
    
    if (unlocked.length === 0) {
      list.innerHTML = '<span style="font-size: 12px; color: #666;">No badges yet.</span>';
      return;
    }

    const badgeDefs = window.badgeEngine ? window.badgeEngine.BADGES : [];
    let html = '';
    unlocked.forEach(u => {
      const def = badgeDefs.find(b => b.id === u.id);
      if (def) {
        html += `
          <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; width: 60px; height: 60px; background: rgba(0, 255, 102, 0.1); border: 1px solid #00ff66; border-radius: 50%;" title="${def.description}">
            <span style="font-size: 24px;">${def.icon}</span>
          </div>
        `;
      }
    });
    list.innerHTML = html;
  }

  renderLesson(id) {
    if (!window.lessonEngine) return;
    const l = window.lessonEngine.getLesson(id);
    if (!l) return;

    this.container.innerHTML = `
      <div>
        <button class="action-btn" style="margin-bottom: 20px; padding: 5px 10px;" onclick="window.trainingUi.renderDashboard()">← Back</button>
        <div class="glass-panel" style="padding: 30px;">
          <h2 style="margin-top: 0; color: #00f0ff;">${l.title}</h2>
          <div style="font-size: 12px; color: #aaa; margin-bottom: 30px;">${l.category} • ${l.estimatedMinutes} mins</div>
          
          <div style="line-height: 1.6; font-size: 14px; color: #ccc;">
            ${l.content}
          </div>
          
          <div style="margin-top: 40px; text-align: center;">
            <button class="action-btn" style="border-color: #00ff66; color: #00ff66; padding: 10px 30px;" onclick="window.trainingUi.completeLesson('${l.id}')">Mark as Completed</button>
          </div>
        </div>
      </div>
    `;
  }

  async completeLesson(id) {
    if (!window.lessonEngine) return;
    const newlyCompleted = await window.lessonEngine.markCompleted(id);
    if (newlyCompleted && window.addLogLine) {
      addLogLine(`[TRAINING] Lesson completed! Earned 50 XP.`, 'success');
    }
    this.renderDashboard();
  }

  renderQuiz(id) {
    if (!window.quizEngine) return;
    const q = window.quizEngine.getQuiz(id);
    if (!q) return;

    let html = `
      <div>
        <button class="action-btn" style="margin-bottom: 20px; padding: 5px 10px;" onclick="window.trainingUi.renderDashboard()">← Back</button>
        <div class="glass-panel" style="padding: 30px;">
          <h2 style="margin-top: 0; color: #ffaa00;">${q.title}</h2>
          <form id="quiz-form-${q.id}" onsubmit="event.preventDefault(); window.trainingUi.submitQuiz('${q.id}')">
    `;

    q.questions.forEach((question, idx) => {
      html += `
        <div style="margin: 25px 0; background: rgba(255,255,255,0.02); padding: 15px; border-left: 2px solid #ffaa00;">
          <div style="font-weight: bold; margin-bottom: 15px; color: #fff;">${idx + 1}. ${question.question}</div>
      `;
      
      question.options.forEach((opt, optIdx) => {
        html += `
          <label style="display: block; margin-bottom: 10px; cursor: pointer;">
            <input type="radio" name="q_${question.id}" value="${optIdx}" required style="margin-right: 10px;">
            ${opt}
          </label>
        `;
      });
      html += `</div>`;
    });

    html += `
            <div style="text-align: center; margin-top: 30px;">
              <button type="submit" class="action-btn" style="border-color: #ffaa00; color: #ffaa00; padding: 10px 30px;">Submit Answers</button>
            </div>
          </form>
        </div>
      </div>
    `;

    this.container.innerHTML = html;
  }

  async submitQuiz(quizId) {
    const form = document.getElementById(`quiz-form-${quizId}`);
    if (!form || !window.quizEngine) return;

    const q = window.quizEngine.getQuiz(quizId);
    let answers = {};
    
    q.questions.forEach(question => {
      const selected = form.querySelector(`input[name="q_${question.id}"]:checked`);
      if (selected) {
        answers[question.id] = parseInt(selected.value, 10);
      }
    });

    const result = window.quizEngine.evaluateAnswers(quizId, answers);
    await window.quizEngine.saveAttempt(result);

    let html = `
      <div>
        <button class="action-btn" style="margin-bottom: 20px; padding: 5px 10px;" onclick="window.trainingUi.renderDashboard()">← Back</button>
        <div class="glass-panel" style="padding: 30px;">
          <h2 style="margin-top: 0; color: ${result.passed ? '#00ff66' : '#ff003c'};">Score: ${Math.round(result.score)}%</h2>
          <p>${result.passed ? 'Passed!' : 'Did not meet passing score.'}</p>
          <div style="margin-top: 20px;">
    `;

    result.results.forEach(res => {
      html += `
        <div style="margin: 15px 0; background: rgba(255,255,255,0.02); padding: 15px; border-left: 2px solid ${res.isCorrect ? '#00ff66' : '#ff003c'};">
          <div style="font-weight: bold; color: ${res.isCorrect ? '#00ff66' : '#ff003c'};">${res.isCorrect ? 'Correct' : 'Incorrect'}</div>
          <div style="margin-top: 10px; font-size: 13px; color: #ccc;">${res.explanation}</div>
        </div>
      `;
    });

    html += `
          </div>
          <div style="text-align: center; margin-top: 30px;">
            <button class="action-btn" onclick="window.trainingUi.renderDashboard()">Finish</button>
          </div>
        </div>
      </div>
    `;

    this.container.innerHTML = html;
  }

  renderChallenge(id) {
    const c = (window.TrainingData.challenges || []).find(x => x.id === id);
    const ctf = (window.TrainingData.ctf || []).find(x => x.id === id);

    if (c) {
      this._renderStandardChallenge(c);
    } else if (ctf) {
      this._renderCtf(ctf);
    }
  }

  _renderStandardChallenge(c) {
    let html = `
      <div>
        <button class="action-btn" style="margin-bottom: 20px; padding: 5px 10px;" onclick="window.trainingUi.renderDashboard()">← Back</button>
        <div class="glass-panel" style="padding: 30px;">
          <h2 style="margin-top: 0; color: #ff003c;">${c.title}</h2>
          <p>${c.description}</p>
          <pre style="background: #111; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 12px; color: #00f0ff; margin: 20px 0;">${c.evidence}</pre>
          
          <div style="margin: 25px 0; background: rgba(255,255,255,0.02); padding: 15px;">
            <div style="font-weight: bold; margin-bottom: 15px; color: #fff;">${c.question}</div>
            <form id="chal-form-${c.id}" onsubmit="event.preventDefault(); window.trainingUi.submitChallenge('${c.id}')">
    `;

    c.options.forEach((opt, idx) => {
      html += `
        <label style="display: block; margin-bottom: 10px; cursor: pointer;">
          <input type="radio" name="c_${c.id}" value="${idx}" required style="margin-right: 10px;">
          ${opt}
        </label>
      `;
    });

    html += `
              <div id="chal-feedback-${c.id}" style="margin-top: 20px; display: none; padding: 10px;"></div>
              <div style="text-align: center; margin-top: 30px;">
                <button type="submit" class="action-btn" style="border-color: #ff003c; color: #ff003c; padding: 10px 30px;">Submit Answer</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    `;

    this.container.innerHTML = html;
  }

  async submitChallenge(id) {
    const form = document.getElementById(`chal-form-${id}`);
    const selected = form.querySelector(`input[name="c_${id}"]:checked`);
    if (!selected || !window.challengeEngine) return;

    const answerIdx = parseInt(selected.value, 10);
    const result = await window.challengeEngine.submitAnswer(id, answerIdx);

    const feedback = document.getElementById(`chal-feedback-${id}`);
    feedback.style.display = 'block';
    feedback.style.borderLeft = `3px solid ${result.isCorrect ? '#00ff66' : '#ff003c'}`;
    feedback.style.background = 'rgba(255,255,255,0.05)';
    feedback.innerHTML = `
      <div style="font-weight: bold; color: ${result.isCorrect ? '#00ff66' : '#ff003c'};">${result.isCorrect ? 'Correct!' : 'Incorrect.'}</div>
      <div style="margin-top: 5px; font-size: 12px; color: #ccc;">${result.explanation}</div>
    `;
    
    if (result.isCorrect) {
      if (window.addLogLine) addLogLine(`[TRAINING] Challenge completed successfully.`, 'success');
    }
  }

  _renderCtf(ctf) {
    let html = `
      <div>
        <button class="action-btn" style="margin-bottom: 20px; padding: 5px 10px;" onclick="window.trainingUi.renderDashboard()">← Back</button>
        <div class="glass-panel" style="padding: 30px;">
          <h2 style="margin-top: 0; color: #ff003c;">${ctf.title} (CTF)</h2>
          <pre style="background: #111; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 13px; color: #00f0ff; margin: 20px 0;">${ctf.description}</pre>
          
          <div style="margin-top: 20px; display: flex; gap: 10px;">
            ${(ctf.hints || []).map(h => `<button type="button" class="action-btn secondary-action" style="font-size: 10px;" onclick="window.trainingUi.useHint('${ctf.id}', ${h.id})">Hint ${h.id} (-${h.penalty}pts)</button>`).join('')}
          </div>
          <div id="ctf-hints-${ctf.id}" style="margin-top: 15px; font-size: 12px; color: #ffaa00;"></div>

          <form id="ctf-form-${ctf.id}" onsubmit="event.preventDefault(); window.trainingUi.submitCtf('${ctf.id}')" style="margin-top: 30px;">
            <input type="text" id="ctf-flag-${ctf.id}" class="hacker-input" placeholder="TV{flag_here}" style="width: 100%; margin-bottom: 15px;" required>
            <div id="ctf-feedback-${ctf.id}" style="margin-bottom: 15px; font-size: 12px; display: none;"></div>
            <button type="submit" class="action-btn" style="width: 100%; border-color: #ff003c; color: #ff003c;">Submit Flag</button>
          </form>
        </div>
      </div>
    `;
    this.container.innerHTML = html;
  }

  async useHint(ctfId, hintId) {
    if (!window.ctfEngine) return;
    const text = await window.ctfEngine.useHint(ctfId, hintId);
    if (text) {
      const el = document.getElementById(`ctf-hints-${ctfId}`);
      if (el) el.innerHTML += `<div><strong>Hint ${hintId}:</strong> ${text}</div>`;
    }
  }

  async submitCtf(ctfId) {
    const input = document.getElementById(`ctf-flag-${ctfId}`);
    if (!input || !window.ctfEngine) return;

    const flag = input.value;
    const result = await window.ctfEngine.submitFlag(ctfId, flag);

    const feedback = document.getElementById(`ctf-feedback-${ctfId}`);
    feedback.style.display = 'block';
    if (result.isValid) {
      feedback.style.color = '#00ff66';
      feedback.textContent = 'Correct Flag! Challenge solved.';
      if (window.addLogLine) addLogLine(`[TRAINING] CTF Flag Accepted!`, 'success');
    } else {
      feedback.style.color = '#ff003c';
      feedback.textContent = 'Invalid flag. Try again.';
    }
  }

  async checkAndRenderCertificate(courseId) {
    if (!window.certificateRenderer) return;
    try {
      const cert = await window.certificateRenderer.generateCertificate(courseId);
      window.certificateRenderer.printCertificate(cert);
    } catch (e) {
      alert("Cannot generate certificate: " + e.message);
    }
  }

  async resetProgress() {
    if (confirm("Are you sure you want to completely reset all training progress, levels, and badges? This does NOT affect scan history.")) {
      if (window.progressManager) {
        await window.progressManager.resetTrainingProgress();
        if (window.addLogLine) addLogLine(`[SYSTEM] Training progress reset.`, 'system');
        this.renderDashboard();
      }
    }
  }
}

if (typeof window !== 'undefined') window.trainingUi = new TrainingUi();
