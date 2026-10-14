/**
 * ScamSense AI - Explainable Analysis Engine
 * Transparent, heuristic-based scam detection and explanation generator.
 */

const { RED_FLAG_PATTERNS, PROTECTIVE_PATTERNS, DEMO_PRESETS } = require('./patterns');

/**
 * Validates input text
 * @param {string} text 
 * @returns {{ valid: boolean, error?: string, cleanText?: string }}
 */
function validateInput(text) {
  if (text === null || text === undefined || typeof text !== 'string') {
    return { valid: false, error: 'Please enter or paste a message to analyze.' };
  }
  const clean = text.trim();
  if (clean.length === 0) {
    return { valid: false, error: 'Message cannot be empty. Please paste an SMS, email, or job offer to analyze.' };
  }
  if (clean.length < 5) {
    return { valid: false, error: 'Message is too short (minimum 5 characters). Please paste the complete message text.' };
  }
  return { valid: true, cleanText: clean };
}

/**
 * Escapes regex special characters in a string
 */
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Highlight matched suspicious phrases in the original text
 * @param {string} text 
 * @param {Array<{ matchedText: string, category: string, severity: string }>} findings 
 * @returns {string} Safe HTML with marked phrases
 */
function generateHighlightedHtml(text, findings) {
  if (!findings || findings.length === 0) {
    // Just escape HTML
    return escapeHtml(text);
  }

  // Collect distinct phrase matches
  const phrases = findings
    .map(f => f.matchedText)
    .filter(Boolean)
    .sort((a, b) => b.length - a.length); // Longest first to avoid partial overlap bugs

  let result = escapeHtml(text);

  // Replace each phrase with a highlighted span
  for (const phrase of phrases) {
    const escapedPhrase = escapeHtml(phrase);
    const regex = new RegExp(`(${escapeRegex(escapedPhrase)})`, 'gi');
    result = result.replace(regex, '<mark class="suspicious-phrase" title="Detected Red Flag">$1</mark>');
  }

  return result;
}

/**
 * Basic HTML escaping helper
 */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
    .replace(/\n/g, '<br/>');
}

/**
 * Core explainable analysis function
 * @param {string} rawText 
 * @param {object} options 
 * @returns {object} Full explainable assessment
 */
function analyzeMessage(rawText, options = {}) {
  const startTime = Date.now();

  const validation = validateInput(rawText);
  if (!validation.valid) {
    return {
      success: false,
      error: validation.error,
      timestamp: new Date().toISOString()
    };
  }

  const text = validation.cleanText;
  const findings = [];
  const protectiveSignals = [];
  const categoryCounts = {};

  let rawRiskScore = 0;

  // 1. Evaluate Red Flags
  for (const pattern of RED_FLAG_PATTERNS) {
    const match = text.match(pattern.regex);
    if (match) {
      const matchedSnippet = match[0].trim();
      findings.push({
        id: pattern.id,
        name: pattern.name,
        category: pattern.category,
        severity: pattern.severity,
        weight: pattern.weight,
        matchedText: matchedSnippet,
        explanation: pattern.explanation,
        safeNextStep: pattern.safeNextStep
      });

      rawRiskScore += pattern.weight;
      categoryCounts[pattern.category] = (categoryCounts[pattern.category] || 0) + 1;
    }
  }

  // 2. Evaluate Protective Signals
  let totalProtection = 0;
  for (const pattern of PROTECTIVE_PATTERNS) {
    const match = text.match(pattern.regex);
    if (match) {
      const matchedSnippet = match[0].trim();
      protectiveSignals.push({
        id: pattern.id,
        name: pattern.name,
        matchedText: matchedSnippet,
        reduction: pattern.reduction,
        explanation: pattern.explanation
      });
      totalProtection += pattern.reduction;
    }
  }

  // 3. Compute Final Score & Tier
  let finalScore = Math.max(0, rawRiskScore - totalProtection);
  // Cap at 100
  finalScore = Math.min(100, Math.round(finalScore));

  let riskCategory = 'Lower Concern';
  let badgeColor = 'emerald';
  let riskSummary = 'No strong deceptive indicators detected in this snippet. Standard vigilance is recommended.';

  const hasCriticalRedFlag = findings.some(f => f.severity === 'critical');

  if ((finalScore >= 66) || (hasCriticalRedFlag && totalProtection < 25)) {
    riskCategory = 'High Risk';
    badgeColor = 'rose';
    finalScore = Math.max(finalScore, 75); // Ensure critical findings sit in High Risk bracket
    riskSummary = 'Multiple critical indicators of fraud, deception, or extortion detected. Do not send money, OTPs, or identity documents.';
  } else if (finalScore >= 30) {
    riskCategory = 'Suspicious';
    badgeColor = 'amber';
    riskSummary = 'Warning signs detected that resemble common scam tactics. Verify credentials thoroughly before taking any action.';
  } else {
    riskCategory = 'Lower Concern';
    badgeColor = 'emerald';
    finalScore = Math.min(finalScore, 25);
    riskSummary = 'Message exhibits characteristics consistent with standard informational or transactional notices. Exercise regular caution.';
  }

  // 4. Synthesize Tailored Next Steps
  const nextSteps = [];
  const seenSteps = new Set();

  for (const finding of findings) {
    if (finding.safeNextStep && !seenSteps.has(finding.safeNextStep)) {
      nextSteps.push({
        title: finding.name,
        action: finding.safeNextStep,
        severity: finding.severity
      });
      seenSteps.add(finding.safeNextStep);
    }
  }

  // Fallback / standard steps if low risk or empty findings
  if (nextSteps.length === 0) {
    nextSteps.push({
      title: 'Standard Verification',
      action: 'Always confirm unexpected alerts directly through the official app, campus portal, or verified website rather than third-party contacts.',
      severity: 'low'
    });
    nextSteps.push({
      title: 'Guard Sensitive Codes',
      action: 'Remember that legitimate organizations will never call or message to ask for your passwords, OTPs, or UPI PINs.',
      severity: 'low'
    });
  }

  // 5. Generate Safe Highlighted HTML for Evidence Display
  const highlightedHtml = generateHighlightedHtml(text, findings);

  const durationMs = Date.now() - startTime;

  return {
    success: true,
    riskScore: finalScore,
    riskCategory, // "Lower Concern" | "Suspicious" | "High Risk"
    badgeColor,
    riskSummary,
    metrics: {
      findingsCount: findings.length,
      protectiveSignalsCount: protectiveSignals.length,
      charLength: text.length,
      wordCount: text.split(/\s+/).filter(Boolean).length,
      durationMs
    },
    findings,
    protectiveSignals,
    categoryBreakdown: categoryCounts,
    safeNextSteps: nextSteps,
    highlightedHtml,
    engineInfo: {
      mode: 'Transparent Rule-Based Heuristic (Demo Mode)',
      modelUsed: 'None (Local Heuristic Threat Engine)',
      isAiApiKeyConfigured: false,
      privacyNote: 'Analysis was performed locally in-memory. Message content is not permanently stored or transmitted to external AI APIs.',
      disclaimer: 'Disclaimer: This automated risk assessment is an educational advisory tool and not definitive legal proof of fraud or authenticity. Scammers continuously adapt tactics. Always verify independently through trusted official channels.'
    },
    timestamp: new Date().toISOString()
  };
}

/**
 * Compare two messages side-by-side
 * @param {string} messageA 
 * @param {string} messageB 
 * @returns {object} Comparative analysis result
 */
function compareMessages(messageA, messageB) {
  const resultA = analyzeMessage(messageA);
  const resultB = analyzeMessage(messageB);

  if (!resultA.success || !resultB.success) {
    return {
      success: false,
      error: !resultA.success ? `Message A Error: ${resultA.error}` : `Message B Error: ${resultB.error}`
    };
  }

  let verdict = '';
  let saferMessage = '';

  if (resultA.riskScore > resultB.riskScore) {
    saferMessage = 'Message B';
    verdict = `Message B is significantly safer (Risk Score: ${resultB.riskScore} vs ${resultA.riskScore}). Message A exhibits ${resultA.findings.length} red flag(s), including upfront payment or urgency demands.`;
  } else if (resultB.riskScore > resultA.riskScore) {
    saferMessage = 'Message A';
    verdict = `Message A is significantly safer (Risk Score: ${resultA.riskScore} vs ${resultB.riskScore}). Message B exhibits ${resultB.findings.length} red flag(s), including upfront payment or urgency demands.`;
  } else {
    saferMessage = 'Equal Risk Tier';
    verdict = `Both messages have similar risk characteristics (Risk Scores: ${resultA.riskScore} vs ${resultB.riskScore}) in the "${resultA.riskCategory}" category.`;
  }

  return {
    success: true,
    messageA: resultA,
    messageB: resultB,
    comparison: {
      saferMessage,
      scoreDifference: Math.abs(resultA.riskScore - resultB.riskScore),
      verdict,
      keyDifferences: [
        `Message A Red Flags: ${resultA.findings.length} flag(s) (${resultA.riskCategory})`,
        `Message B Red Flags: ${resultB.findings.length} flag(s) (${resultB.riskCategory})`,
        `Protective Signals: Message A has ${resultA.protectiveSignals.length}, Message B has ${resultB.protectiveSignals.length}`
      ]
    }
  };
}

module.exports = {
  validateInput,
  analyzeMessage,
  compareMessages,
  generateHighlightedHtml,
  DEMO_PRESETS
};
