/**
 * server.js
 * Main Express server for Cyber Nexus.
 * Provides APIs for email header spoofing analysis and file attachment scanning.
 */

const express = require('express');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');

const { analyzeHeaders } = require('./public/utils/headerAnalyzer');
const { analyzeFile } = require('./public/utils/fileScanner');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure body-parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static assets from public folder
app.use(express.static(path.join(__dirname, 'public')));

// Configure Multer for file uploads (temporary storage)
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}
const upload = multer({ dest: 'uploads/' });

/**
 * API Endpoint: Analyze Email Headers
 * POST /api/analyze-headers
 */
app.post('/api/analyze-headers', (req, res) => {
  try {
    const { headers } = req.body;
    if (!headers) {
      return res.status(400).json({ error: 'No email headers provided for analysis.' });
    }
    
    const results = analyzeHeaders(headers);
    res.json(results);
  } catch (err) {
    console.error('Error in /api/analyze-headers:', err);
    res.status(500).json({ error: 'Failed to analyze email headers.' });
  }
});

/**
 * API Endpoint: Scan File Attachment
 * POST /api/scan-file
 */
app.post('/api/scan-file', upload.single('attachment'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file attachment provided for scanning.' });
    }

    const filePath = req.file.path;
    const filename = req.file.originalname;

    // Read file contents
    const fileBuffer = fs.readFileSync(filePath);
    
    // Compute SHA-256 hash
    const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    // Attempt to convert to string to scan for script patterns
    const contentString = fileBuffer.toString('utf8');

    // Run file analysis
    const results = analyzeFile(filename, contentString, sha256);

    // Add extra metadata to response
    results.hash = sha256;
    results.size = req.file.size;

    // Clean up temporary uploaded file asynchronously
    fs.unlink(filePath, (err) => {
      if (err) console.error('Error deleting temp upload file:', err);
    });

    res.json(results);
  } catch (err) {
    console.error('Error in /api/scan-file:', err);
    res.status(500).json({ error: 'Failed to scan the file attachment.' });
  }
});

/**
 * API Endpoint: Analyze Raw EML File
 * POST /api/scan-eml
 */
app.post('/api/scan-eml', upload.single('emlFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No EML file provided.' });
    }

    const filePath = req.file.path;
    const fileBuffer = fs.readFileSync(filePath);

    let simpleParser;
    try {
      simpleParser = require('mailparser').simpleParser;
    } catch (e) {
      // Return error if mailparser isn't installed
      fs.unlinkSync(filePath);
      return res.status(500).json({ 
        error: 'Mailparser library is not installed on the server. Cannot process .eml files directly.' 
      });
    }

    // Parse EML file using mailparser
    const email = await simpleParser(fileBuffer);
    
    // Extract headers (join header keys and values)
    let rawHeaders = '';
    email.headers.forEach((value, key) => {
      if (Array.isArray(value)) {
        value.forEach(val => {
          rawHeaders += `${key}: ${typeof val === 'object' ? JSON.stringify(val) : val}\n`;
        });
      } else if (typeof value === 'object') {
        rawHeaders += `${key}: ${JSON.stringify(value)}\n`;
      } else {
        rawHeaders += `${key}: ${value}\n`;
      }
    });

    // Run header spoofing analyzer
    const headerResults = analyzeHeaders(rawHeaders);

    // Check attachments
    const attachmentResults = [];
    if (email.attachments && email.attachments.length > 0) {
      for (const attachment of email.attachments) {
        const attachHash = crypto.createHash('sha256').update(attachment.content).digest('hex');
        const contentStr = attachment.content.toString('utf8');
        const scan = analyzeFile(attachment.filename, contentStr, attachHash);
        
        attachmentResults.push({
          filename: attachment.filename,
          contentType: attachment.contentType,
          size: attachment.size,
          hash: attachHash,
          results: scan
        });
      }
    }

    // Clean up temporary file
    fs.unlink(filePath, (err) => {
      if (err) console.error('Error deleting temp EML file:', err);
    });

    res.json({
      subject: email.subject,
      from: email.from ? email.from.text : 'Unknown',
      to: email.to ? email.to.text : 'Unknown',
      date: email.date,
      headerResults,
      attachments: attachmentResults
    });

  } catch (err) {
    console.error('Error in /api/scan-eml:', err);
    res.status(500).json({ error: 'Failed to process EML file.' });
  }
});

// Start listening
app.listen(PORT, () => {
  console.log(`==================================================`);
  console.log(`  Trust & Verify Security Engine Running on Port ${PORT}`);
  console.log(`  Access dashboard: http://localhost:${PORT}`);
  console.log(`==================================================`);
});
