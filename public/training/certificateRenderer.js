// certificateRenderer.js

class CertificateRenderer {
  constructor() {
    this.data = window.TrainingData || {};
  }

  async checkCourseCompletion(courseId) {
    if (!window.progressManager) return false;
    
    const course = this.data.courses.find(c => c.id === courseId);
    if (!course) return false;

    // Check required lessons
    for (const lId of course.requiredLessons) {
      const p = await window.progressManager.getProgress(lId);
      if (!p || p.status !== 'COMPLETED') return false;
    }

    // Check required quizzes
    let totalScore = 0;
    for (const qId of course.requiredQuizzes) {
      const att = await window.progressManager.getQuizAttempt(qId);
      if (!att || !att.passed) return false;
      totalScore += att.bestScore;
    }

    const averageScore = totalScore / course.requiredQuizzes.length;
    if (averageScore < course.requiredScore) return false;

    return { completed: true, averageScore };
  }

  async generateCertificate(courseId, learnerName = "Local Learner") {
    const status = await this.checkCourseCompletion(courseId);
    if (!status || !status.completed) {
      throw new Error("Course requirements not fully met.");
    }

    const course = this.data.courses.find(c => c.id === courseId);
    
    // Generate deterministic-looking random ID using Web Crypto if available
    const array = new Uint32Array(3);
    window.crypto.getRandomValues(array);
    const certId = `TV-CERT-${array[0].toString(16)}-${array[1].toString(16)}-${array[2].toString(16)}`.toUpperCase();
    
    const cert = {
      id: certId,
      courseId,
      courseTitle: course.title,
      learnerName,
      score: Math.round(status.averageScore),
      issueDate: new Date().toISOString()
    };

    if (window.progressManager) {
      const existingCerts = await window.progressManager.getCertificates();
      const alreadyHas = existingCerts.find(c => c.courseId === courseId);
      if (!alreadyHas) {
        await window.progressManager.saveCertificate(cert);
        if (window.gamificationEngine) {
          await window.gamificationEngine.awardPoints('COURSE_COMPLETED', courseId, course.rewardPoints || 500);
        }
      } else {
        return alreadyHas;
      }
    }

    return cert;
  }

  printCertificate(cert) {
    // Basic XSS protection for names
    const escapeHtml = (unsafe) => {
      if (typeof unsafe !== 'string') return '';
      return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    };

    const safeName = escapeHtml(cert.learnerName);
    const dateStr = new Date(cert.issueDate).toLocaleDateString();

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Certificate - ${cert.id}</title>
        <style>
          body { font-family: 'Courier New', monospace; text-align: center; background: #000; color: #00f0ff; padding: 50px; }
          .cert-container { border: 2px solid #00f0ff; padding: 40px; border-radius: 10px; box-shadow: 0 0 20px rgba(0, 240, 255, 0.2); }
          h1 { color: #fff; text-transform: uppercase; letter-spacing: 2px; }
          h2 { color: #ffaa00; }
          .name { font-size: 24px; color: #fff; margin: 20px 0; font-weight: bold; }
          .details { margin-top: 40px; font-size: 14px; color: #aaa; text-align: left; }
          .stamp { border: 1px solid #ff003c; color: #ff003c; padding: 10px; display: inline-block; transform: rotate(-5deg); margin-top: 30px; }
          @media print {
            body { background: #fff; color: #000; }
            .cert-container { border: 2px solid #000; box-shadow: none; }
            h1, .name { color: #000; }
            h2 { color: #333; }
            .details { color: #555; }
          }
        </style>
      </head>
      <body>
        <div class="cert-container">
          <h1>Trust & Verify</h1>
          <p>Security Awareness Training</p>
          
          <div style="margin: 40px 0;">
            <p>This certifies that</p>
            <div class="name">${safeName}</div>
            <p>has successfully completed the course:</p>
            <h2>${cert.courseTitle}</h2>
          </div>
          
          <div class="stamp">LOCAL EDUCATIONAL COMPLETION ONLY<br>NO EXTERNAL ACCREDITATION</div>
          
          <div class="details">
            <p>Score: ${cert.score}%</p>
            <p>Date: ${dateStr}</p>
            <p>Certificate ID: ${cert.id}</p>
          </div>
        </div>
        <script>
          setTimeout(() => window.print(), 500);
        </script>
      </body>
      </html>
    `;
    
    const printWindow = window.open('', '_blank');
    printWindow.document.write(html);
    printWindow.document.close();
  }
}

if (typeof window !== 'undefined') window.certificateRenderer = new CertificateRenderer();
