/**
 * ScamSense AI - In-Memory OCR Engine
 * Optical character recognition using Tesseract.js.
 * Operates strictly in-memory without persisting uploaded image files to disk.
 */

const Tesseract = require('tesseract.js');

/**
 * Extracts text from an image buffer or file path using Tesseract OCR
 * @param {Buffer|string} imageSource Buffer containing image data or file path
 * @param {object} [options] Optional configuration
 * @returns {Promise<{ success: boolean, text?: string, confidence?: number, error?: string }>}
 */
async function extractTextFromImage(imageSource, options = {}) {
  if (!imageSource) {
    return {
      success: false,
      error: 'No image data provided for OCR analysis.'
    };
  }

  // If buffer, verify it is non-empty
  if (Buffer.isBuffer(imageSource) && imageSource.length === 0) {
    return {
      success: false,
      error: 'Uploaded image file is empty (0 bytes).'
    };
  }

  try {
    const result = await Tesseract.recognize(
      imageSource,
      'eng',
      {
        errorHandler: err => console.error('Tesseract inner warning:', err)
      }
    );

    const rawText = (result && result.data && result.data.text) ? result.data.text : '';
    const cleanText = rawText.trim();
    const confidence = (result && result.data && typeof result.data.confidence === 'number')
      ? Math.round(result.data.confidence)
      : null;

    // If no meaningful text extracted (less than 5 readable characters)
    if (cleanText.length < 5) {
      return {
        success: false,
        error: 'Could not extract readable text from this image. The image may be blank, blurry, or low resolution. Please try a clearer screenshot or paste the text manually into the text area.',
        confidence
      };
    }

    return {
      success: true,
      text: cleanText,
      confidence
    };
  } catch (err) {
    console.error('OCR Processing Error:', err.message || err);
    return {
      success: false,
      error: 'An error occurred while processing the image with OCR. Please ensure the file is a valid PNG or JPEG screenshot, or paste the text manually.'
    };
  }
}

module.exports = {
  extractTextFromImage
};
