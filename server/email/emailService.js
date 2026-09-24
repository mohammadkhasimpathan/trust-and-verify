const nodemailer = require('nodemailer');

const EMAIL_MODE = process.env.EMAIL_MODE || 'console'; // 'console' or 'smtp'

let transporter;
if (EMAIL_MODE === 'smtp') {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    }
  });
}

async function sendEmail({ to, subject, text, html }) {
  if (EMAIL_MODE === 'console') {
    console.log('====================================================');
    console.log(`[EMAIL MOCK] To: ${to}`);
    console.log(`[EMAIL MOCK] Subject: ${subject}`);
    console.log(`[EMAIL MOCK] Body: \n${text}`);
    console.log('====================================================');
    return { success: true, mode: 'console' };
  } else {
    try {
      const info = await transporter.sendMail({
        from: process.env.EMAIL_FROM || '"Trust & Verify" <noreply@trustverify.example>',
        to,
        subject,
        text,
        html
      });
      return { success: true, messageId: info.messageId };
    } catch (err) {
      console.error('[EMAIL ERROR]', err);
      return { success: false, error: err.message };
    }
  }
}

module.exports = {
  sendEmail
};
