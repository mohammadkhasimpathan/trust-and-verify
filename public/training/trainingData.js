// trainingData.js
/**
 * Static educational content for Trust & Verify Phase 6.
 * Content is completely separated from user progress.
 */

const TrainingData = {
  version: "1.0",
  courses: [
    {
      id: "course_fundamentals",
      title: "Cybersecurity Awareness Fundamentals",
      description: "Essential concepts to protect yourself and your organization from common cyber threats.",
      requiredLessons: ["lesson_phishing", "lesson_urls", "lesson_social_eng"],
      requiredQuizzes: ["quiz_phishing", "quiz_urls", "quiz_social_eng"],
      requiredScore: 80,
      rewardPoints: 500
    }
  ],

  lessons: [
    {
      id: "lesson_phishing",
      category: "Phishing Awareness",
      title: "Spotting Phishing Emails",
      difficulty: "BEGINNER",
      estimatedMinutes: 5,
      objectives: [
        "Identify common phishing indicators",
        "Distinguish sender address from display name",
        "Explain why urgency is commonly used"
      ],
      content: `
        <h3>What is Phishing?</h3>
        <p>Phishing is a cyberattack that uses disguised email as a weapon. The goal is to trick the email recipient into believing that the message is something they want or need — a request from their bank, for instance, or a note from someone in their company — and to click a link or download an attachment.</p>
        
        <h3>Key Indicators</h3>
        <ul>
          <li><strong>Mismatched Domains:</strong> The display name says 'PayPal' but the email address is 'security@paypal-update.com'.</li>
          <li><strong>Urgency:</strong> 'Your account will be suspended in 24 hours if you do not verify.'</li>
          <li><strong>Suspicious Links:</strong> The text says 'Log In' but hovering over it reveals a strange domain.</li>
        </ul>
        
        <div style="background: rgba(255,255,255,0.05); padding: 15px; border-left: 3px solid #ffaa00; margin: 20px 0;">
          <strong>Example:</strong><br>
          From: Apple Support &lt;support@apple.billing-services.com&gt;<br>
          Subject: URGENT: Your Apple ID has been locked<br>
          <br>
          This is suspicious because the domain is 'billing-services.com', not 'apple.com'.
        </div>
      `,
      quizId: "quiz_phishing"
    },
    {
      id: "lesson_urls",
      category: "URL Security",
      title: "Deconstructing URLs",
      difficulty: "INTERMEDIATE",
      estimatedMinutes: 10,
      objectives: [
        "Identify the registrable domain",
        "Understand subdomains vs domains",
        "Recognize look-alike domains"
      ],
      content: `
        <h3>The Anatomy of a URL</h3>
        <p>A URL (Uniform Resource Locator) consists of several parts. Understanding these parts is crucial for identifying malicious links.</p>
        
        <p><strong>https://secure.login.example.com/verify</strong></p>
        <ul>
          <li><strong>Protocol:</strong> https (Encrypted)</li>
          <li><strong>Subdomains:</strong> secure.login</li>
          <li><strong>Registrable Domain:</strong> example.com (This is what you must verify!)</li>
          <li><strong>Path:</strong> /verify</li>
        </ul>
        
        <h3>The Subdomain Trick</h3>
        <p>Attackers often put trusted brand names in the subdomain to trick you. For example: <code>https://paypal.com.secure-login.net</code>. The actual domain here is <code>secure-login.net</code>, not PayPal.</p>
      `,
      quizId: "quiz_urls"
    },
    {
      id: "lesson_social_eng",
      category: "Social Engineering",
      title: "The Human Firewall",
      difficulty: "BEGINNER",
      estimatedMinutes: 5,
      objectives: [
        "Recognize social engineering tactics",
        "Understand the principles of authority and urgency"
      ],
      content: `
        <h3>Hacking the Human</h3>
        <p>Social engineering is the art of manipulating people so they give up confidential information. The types of information these criminals are seeking can vary, but when individuals are targeted the criminals are usually trying to trick you into giving them your passwords or bank information.</p>
        
        <h3>Common Tactics</h3>
        <ul>
          <li><strong>Authority:</strong> Pretending to be the CEO, IT Support, or Law Enforcement.</li>
          <li><strong>Urgency:</strong> 'We need this wire transfer immediately or we lose the contract.'</li>
          <li><strong>Scarcity:</strong> 'Only 3 spots left for this exclusive offer.'</li>
        </ul>
        
        <p><strong>Defense:</strong> Always verify requests through a secondary, trusted channel. If the 'CEO' emails you for gift cards, call the CEO using the number in your corporate directory.</p>
      `,
      quizId: "quiz_social_eng"
    }
  ],

  quizzes: [
    {
      id: "quiz_phishing",
      lessonId: "lesson_phishing",
      title: "Phishing Knowledge Check",
      passingScore: 100,
      version: "1.0",
      questions: [
        {
          id: "q1",
          type: "single_choice",
          question: "Which of the following is the most reliable way to verify the sender of an email?",
          options: [
            "Check the Display Name",
            "Check the actual 'From' email address domain",
            "Look for the official company logo in the email body",
            "Check the email signature"
          ],
          correctAnswer: 1, // Index of correct option
          explanation: "The Display Name, logos, and signatures can be easily faked. The 'From' address domain is harder to spoof, especially with SPF/DKIM protections."
        },
        {
          id: "q2",
          type: "scenario_choice",
          question: "You receive an email from 'IT Helpdesk' claiming your password expires in 1 hour and you must click a link to keep your access. What is the BEST action?",
          options: [
            "Click the link and change the password immediately to be safe.",
            "Reply to the email asking for confirmation.",
            "Forward the email to your personal account to deal with later.",
            "Do not click the link. Open your browser, navigate to your company's official portal, and check your password status there."
          ],
          correctAnswer: 3,
          explanation: "Never click links in urgent, unsolicited emails. Navigating independently to the official portal ensures you are interacting with the legitimate system."
        }
      ]
    },
    {
      id: "quiz_urls",
      lessonId: "lesson_urls",
      title: "URL Security Check",
      passingScore: 100,
      version: "1.0",
      questions: [
        {
          id: "q3",
          type: "single_choice",
          question: "What is the registrable domain in the URL: https://login.microsoftonline.update-services.com/auth ?",
          options: [
            "microsoftonline.com",
            "update-services.com",
            "login.microsoftonline",
            "auth.com"
          ],
          correctAnswer: 1,
          explanation: "The registrable domain is the right-most part before the top-level domain (.com). Everything before 'update-services' is just a subdomain designed to trick you."
        }
      ]
    },
    {
      id: "quiz_social_eng",
      lessonId: "lesson_social_eng",
      title: "Social Engineering Check",
      passingScore: 100,
      version: "1.0",
      questions: [
        {
          id: "q4",
          type: "single_choice",
          question: "An attacker calls pretending to be your bank and says your account is locked. They need your SMS OTP to 'verify your identity and unlock it'. Why is this dangerous?",
          options: [
            "The bank already knows your password.",
            "The OTP is actually for an attacker trying to log into your account, not unlock it.",
            "Phone calls are never encrypted.",
            "Banks don't use OTPs."
          ],
          correctAnswer: 1,
          explanation: "Attackers often trigger a login attempt which sends an OTP to your phone. By convincing you to read it to them, they bypass your MFA protection."
        }
      ]
    }
  ],
  
  challenges: [
    {
      id: "chal_spot_phish",
      category: "Spot the Phish",
      title: "The CEO Fraud",
      difficulty: "INTERMEDIATE",
      reward: 100,
      description: "Analyze the following email and identify the primary indicator of compromise.",
      evidence: `
From: John Doe (CEO) <ceo@company-executive-board.com>
To: Finance Department
Subject: URGENT: Wire Transfer Required

Hi Team,
I'm currently in a meeting with an acquisition target. I need a wire transfer of $45,000 processed immediately to secure the deal.
Details attached. Please process ASAP.

Thanks,
John Doe
      `,
      question: "What is the most critical red flag in this email?",
      options: [
        "The subject line uses capital letters.",
        "The domain 'company-executive-board.com' is likely a look-alike domain impersonating the real company.",
        "CEOs never ask for wire transfers.",
        "The email has an attachment."
      ],
      correctAnswer: 1,
      explanation: "This is a classic Business Email Compromise (BEC) tactic. The attacker registered a domain that looks related to the company but is entirely under their control."
    }
  ],

  ctf: [
    {
      id: "ctf_01",
      title: "Hidden in Plain Sight",
      difficulty: "BEGINNER",
      reward: 150,
      description: "An attacker left a hidden flag in this seemingly benign URL. Can you find it? \n\nURL: https://example.com/login?redirect=TV%7Burl_encoding_is_fun%7D",
      hints: [
        { id: 1, text: "Look closely at the query parameters.", penalty: 20 },
        { id: 2, text: "The flag starts with TV{ and ends with }. Some characters might be URL encoded.", penalty: 20 }
      ],
      validateLocal: (flag) => flag.trim() === "TV{url_encoding_is_fun}"
    }
  ]
};

if (typeof window !== 'undefined') window.TrainingData = TrainingData;
if (typeof module !== 'undefined') module.exports = TrainingData;
