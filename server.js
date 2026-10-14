/**
 * ScamSense AI - Local Web Application Server
 * Express-based lightweight server serving API endpoints and responsive dashboard.
 */

const express = require('express');
const path = require('path');
const {
  validateInput,
  analyzeMessage,
  compareMessages,
  DEMO_PRESETS
} = require('./engine/analyzer');

const app = express();
const PORT = process.env.PORT || 3000;

// Security and body parsing middlewares
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

// Basic Security Headers without external dependencies
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Serve frontend static assets
app.use(express.static(path.join(__dirname, 'public')));

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    app: 'ScamSense AI',
    version: '1.0.0',
    mode: 'Transparent Rule-Based Heuristic (Demo Mode)',
    aiApiKeyConfigured: false,
    timestamp: new Date().toISOString()
  });
});

// Get demo presets
app.get('/api/presets', (req, res) => {
  res.json({
    success: true,
    presets: DEMO_PRESETS
  });
});

const multer = require('multer');
const { extractTextFromImage } = require('./engine/ocr');

// In-Memory Storage for uploaded screenshots (never written to disk)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5 MB max
  },
  fileFilter: (req, file, cb) => {
    const allowedMimes = ['image/jpeg', 'image/png', 'image/jpg'];
    if (allowedMimes.includes(file.mimetype.toLowerCase())) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPG, JPEG, and PNG images are supported.'));
    }
  }
});

// Analyze single message endpoint (Text)
app.post('/api/analyze', (req, res) => {
  try {
    const { text } = req.body;
    
    // Privacy safeguard: Analysis runs strictly in-memory without persistent logging
    const result = analyzeMessage(text);
    
    if (!result.success) {
      return res.status(400).json(result);
    }
    
    return res.json(result);
  } catch (err) {
    console.error('Analysis error:', err.message);
    return res.status(500).json({
      success: false,
      error: 'An internal error occurred while processing the analysis. Please try again.'
    });
  }
});

// Analyze screenshot/image via OCR endpoint
app.post('/api/analyze-image', (req, res) => {
  upload.single('image')(req, res, async (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
          success: false,
          error: 'The uploaded file is too large. Maximum supported image size is 5 MB.'
        });
      }
      return res.status(400).json({
        success: false,
        error: `Upload error: ${err.message}`
      });
    } else if (err) {
      return res.status(400).json({
        success: false,
        error: err.message || 'Invalid image upload.'
      });
    }

    if (!req.file || !req.file.buffer) {
      return res.status(400).json({
        success: false,
        error: 'No image file uploaded. Please select a PNG or JPG screenshot.'
      });
    }

    try {
      // Perform OCR in-memory (buffer is never saved to disk)
      const ocrResult = await extractTextFromImage(req.file.buffer);

      if (!ocrResult.success) {
        return res.status(422).json({
          success: false,
          error: ocrResult.error,
          isOcrFailure: true
        });
      }

      // Analyze extracted text using existing explainable engine
      const analysisResult = analyzeMessage(ocrResult.text);

      return res.json({
        ...analysisResult,
        isOcr: true,
        extractedText: ocrResult.text,
        ocrConfidence: ocrResult.confidence,
        imageMeta: {
          originalName: req.file.originalname,
          sizeBytes: req.file.size,
          mimetype: req.file.mimetype
        }
      });
    } catch (analysisErr) {
      console.error('Image analysis error:', analysisErr.message);
      return res.status(500).json({
        success: false,
        error: 'Failed to process image OCR analysis. Please try manual text input.'
      });
    }
  });
});

// Compare two messages endpoint
app.post('/api/compare', (req, res) => {
  try {
    const { messageA, messageB } = req.body;
    
    const result = compareMessages(messageA, messageB);
    
    if (!result.success) {
      return res.status(400).json(result);
    }
    
    return res.json(result);
  } catch (err) {
    console.error('Comparison error:', err.message);
    return res.status(500).json({
      success: false,
      error: 'An internal error occurred while comparing messages. Please try again.'
    });
  }
});

// Fallback middleware to index.html for single-page dashboard routing
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start listening if run directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(`🛡️  ScamSense AI is running locally!`);
    console.log(`📍 URL: http://localhost:${PORT}`);
    console.log(`🔒 Mode: Transparent Rule-Based Heuristic (Demo Mode)`);
    console.log(`⚡ Privacy: In-memory analysis. No messages stored.`);
    console.log(`====================================================`);
  });
}

module.exports = app;
