const test = require('node:test');
const assert = require('node:assert/strict');
const {
  validateInput,
  analyzeMessage,
  compareMessages,
  DEMO_PRESETS
} = require('../engine/analyzer');

test('Validation - rejects empty, null, and invalid non-string inputs', () => {
  const emptyRes = validateInput('');
  assert.strictEqual(emptyRes.valid, false);
  assert.match(emptyRes.error, /cannot be empty/i);

  const nullRes = validateInput(null);
  assert.strictEqual(nullRes.valid, false);

  const undefRes = validateInput(undefined);
  assert.strictEqual(undefRes.valid, false);

  const numRes = validateInput(12345);
  assert.strictEqual(numRes.valid, false);

  const objRes = validateInput({ message: 'fake' });
  assert.strictEqual(objRes.valid, false);

  const arrRes = validateInput(['array', 'text']);
  assert.strictEqual(arrRes.valid, false);

  const boolRes = validateInput(false);
  assert.strictEqual(boolRes.valid, false);

  const whitespaceRes = validateInput('    \n\t   ');
  assert.strictEqual(whitespaceRes.valid, false);

  const shortRes = validateInput('Hi');
  assert.strictEqual(shortRes.valid, false);
  assert.match(shortRes.error, /too short/i);

  const validRes = validateInput('This is a valid test snippet for analysis.');
  assert.strictEqual(validRes.valid, true);
  assert.strictEqual(validRes.cleanText, 'This is a valid test snippet for analysis.');
});

test('Analyzer - safely sanitizes and handles HTML and script injection attempts', () => {
  const xssAttempt = '<script>alert("hack")</script> Pay Rs 1999 registration fee immediately.';
  const result = analyzeMessage(xssAttempt);

  assert.strictEqual(result.success, true);
  assert.strictEqual(result.riskCategory, 'High Risk');
  assert.doesNotMatch(result.highlightedHtml, /<script>/i, 'Raw script tags must not be output unescaped');
  assert.match(result.highlightedHtml, /&lt;script&gt;/i, 'Script tags must be safely escaped as HTML entities');
});

test('Analyzer - detects Suspicious Internship Registration Fee Scam as High Risk', () => {
  const internshipScam = DEMO_PRESETS.find(p => p.id === 'demo-internship-scam');
  assert.ok(internshipScam, 'Preset demo-internship-scam should exist');

  const result = analyzeMessage(internshipScam.content);
  assert.strictEqual(result.success, true);
  assert.strictEqual(result.riskCategory, 'High Risk');
  assert.ok(result.riskScore >= 66, `Expected score >= 66, got ${result.riskScore}`);

  // Check specific evidence detected
  const hasFeeFlag = result.findings.some(f => f.category === 'Advance Fee Demanded');
  assert.strictEqual(hasFeeFlag, true, 'Should flag advance fee demanded for internship/training');

  const hasUrgencyFlag = result.findings.some(f => f.category === 'Urgency & Intimidation');
  assert.strictEqual(hasUrgencyFlag, true, 'Should flag high pressure urgency');

  // Verify safe next steps are generated
  assert.ok(result.safeNextSteps.length >= 1, 'Should generate actionable defensive next steps');
  assert.match(result.safeNextSteps[0].action, /never pay|reputable employer/i);

  // Check engine metadata transparency
  assert.strictEqual(result.engineInfo.mode, 'Transparent Rule-Based Heuristic (Demo Mode)');
  assert.strictEqual(result.engineInfo.isAiApiKeyConfigured, false);
});

test('Analyzer - detects Scholarship Fee & Identity Harvesting as High Risk', () => {
  const scholarshipScam = DEMO_PRESETS.find(p => p.id === 'demo-scholarship-fraud');
  assert.ok(scholarshipScam);

  const result = analyzeMessage(scholarshipScam.content);
  assert.strictEqual(result.success, true);
  assert.strictEqual(result.riskCategory, 'High Risk');

  const hasIdentityFlag = result.findings.some(f => f.category === 'Identity Theft Risk');
  assert.strictEqual(hasIdentityFlag, true, 'Should detect sensitive document demand via chat');

  const hasTldFlag = result.findings.some(f => f.category === 'Suspicious Links');
  assert.strictEqual(hasTldFlag, true, 'Should detect suspicious domain extension .top');
});

test('Analyzer - detects KYC Panic Phishing with .xyz link as High Risk', () => {
  const kycPhish = DEMO_PRESETS.find(p => p.id === 'demo-kyc-suspension');
  const result = analyzeMessage(kycPhish.content);

  assert.strictEqual(result.success, true);
  assert.strictEqual(result.riskCategory, 'High Risk');
  assert.ok(result.findings.some(f => f.id === 'KYC_PAN_EXPIRY_THREAT'));
  assert.ok(result.findings.some(f => f.id === 'SUSPICIOUS_TLD_OR_IP'));
});

test('Analyzer - detects Telegram part-time task fraud as Suspicious / High Risk', () => {
  const taskScam = DEMO_PRESETS.find(p => p.id === 'demo-task-fraud');
  const result = analyzeMessage(taskScam.content);

  assert.strictEqual(result.success, true);
  assert.ok(result.riskCategory === 'Suspicious' || result.riskCategory === 'High Risk');
  assert.ok(result.findings.some(f => f.id === 'TASK_FRAUD_LIKE_MAPS'));
});

test('Analyzer - rates Legitimate Campus Placement notice as Lower Concern', () => {
  const placementNotice = DEMO_PRESETS.find(p => p.id === 'demo-legit-campus-placement');
  const result = analyzeMessage(placementNotice.content);

  assert.strictEqual(result.success, true);
  assert.strictEqual(result.riskCategory, 'Lower Concern');
  assert.ok(result.riskScore < 30, `Expected score < 30 for legitimate notice, got ${result.riskScore}`);

  // Should have protective signals
  assert.ok(result.protectiveSignals.length > 0, 'Should detect explicit no-fee confirmation');
  assert.ok(result.protectiveSignals.some(s => s.id === 'NO_FEES_EXPLICIT'));
});

test('Analyzer - rates Legitimate Delivery Alert as Lower Concern', () => {
  const deliveryAlert = DEMO_PRESETS.find(p => p.id === 'demo-legit-delivery-alert');
  const result = analyzeMessage(deliveryAlert.content);

  assert.strictEqual(result.success, true);
  assert.strictEqual(result.riskCategory, 'Lower Concern');
  assert.ok(result.riskScore < 30, `Expected score < 30, got ${result.riskScore}`);
  assert.ok(result.protectiveSignals.some(s => s.id === 'SECURITY_NEVER_ASKS_OTP'));
});

test('Analyzer - handles False Positive Edge Case: Security Newsletter discussing scams', () => {
  const securityNewsletter = `Monthly IT Security Bulletin:
Please be aware that cyber criminals often impersonate HR or bank representatives.
Remember: our university IT department will never ask for your password or credentials.
If you notice any suspicious activity, report it directly to security@university.edu.
Keep your software updated and stay alert.`;

  const result = analyzeMessage(securityNewsletter);
  assert.strictEqual(result.success, true);
  assert.strictEqual(result.riskCategory, 'Lower Concern');
  assert.ok(result.riskScore < 30);
});

test('Analyzer - handles False Positive Edge Case: Legitimate Offer with Salary mention', () => {
  const legitimateJobOffer = `We are pleased to offer you the position of Junior Software Engineer at TechCorp Solutions.
Your annual CTC will be INR 6,50,000 per annum with standard health benefits.
Please review the attached formal offer letter. You may accept the offer by signing through the official DocuSign link within 7 business days.
There are no fees or processing charges required. Welcome aboard!`;

  const result = analyzeMessage(legitimateJobOffer);
  assert.strictEqual(result.success, true);
  assert.strictEqual(result.riskCategory, 'Lower Concern');
});

test('Comparison Mode - compares Scam Internship vs Legitimate Campus Notice', () => {
  const scam = DEMO_PRESETS.find(p => p.id === 'demo-internship-scam').content;
  const legit = DEMO_PRESETS.find(p => p.id === 'demo-legit-campus-placement').content;

  const comp = compareMessages(scam, legit);
  assert.strictEqual(comp.success, true);
  assert.strictEqual(comp.comparison.saferMessage, 'Message B');
  assert.ok(comp.comparison.scoreDifference > 40);
  assert.match(comp.comparison.verdict, /Message B is significantly safer/);
});

test('Analyzer - detects UPI Reversal PIN deception as Critical High Risk', () => {
  const upiFraud = 'Your cashback of Rs 2,500 is pending. Please enter your UPI PIN to receive money in your Google Pay account.';
  const result = analyzeMessage(upiFraud);

  assert.strictEqual(result.success, true);
  assert.strictEqual(result.riskCategory, 'High Risk');
  const upiFinding = result.findings.find(f => f.id === 'UPI_ENTER_PIN_TO_RECEIVE');
  assert.ok(upiFinding, 'Should detect UPI_ENTER_PIN_TO_RECEIVE pattern');
  assert.match(upiFinding.explanation, /NEVER to receive money/i);
});

test('Analyzer - detects Digital Arrest / Law Enforcement intimidation', () => {
  const digitalArrest = 'This is Customs & Police Narcotics Bureau. A parcel with illegal drugs was found in your name. To avoid immediate arrest warrant, connect on Skype and transfer Rs 50,000 security penalty.';
  const result = analyzeMessage(digitalArrest);

  assert.strictEqual(result.success, true);
  assert.strictEqual(result.riskCategory, 'High Risk');
  assert.ok(result.findings.some(f => f.id === 'LEGAL_ARREST_THREAT'));
});

test('Comparison Mode - gracefully handles invalid inputs', () => {
  const res = compareMessages('', 'Valid message with some content here.');
  assert.strictEqual(res.success, false);
  assert.match(res.error, /Message A Error/);

  const res2 = compareMessages('Valid message content here.', '');
  assert.strictEqual(res2.success, false);
  assert.match(res2.error, /Message B Error/);
});

test('OCR Engine - extracts text from suspicious internship screenshot buffer and flags scam', async () => {
  const { extractTextFromImage } = require('../engine/ocr');
  const fs = require('fs');
  const path = require('path');

  const imgPath = path.join(__dirname, 'fixtures/sample_scam.png');
  const buf = fs.readFileSync(imgPath);

  const ocrRes = await extractTextFromImage(buf);
  assert.strictEqual(ocrRes.success, true, 'OCR should successfully extract text');
  assert.ok(ocrRes.text.length > 10, 'Extracted text should be non-trivial');
  assert.match(ocrRes.text, /1999|registration|Google/i);

  // Now analyze the extracted text with the scam engine
  const analysis = analyzeMessage(ocrRes.text);
  assert.strictEqual(analysis.success, true);
  assert.strictEqual(analysis.riskCategory, 'High Risk');
  assert.ok(analysis.findings.some(f => f.category === 'Advance Fee Demanded' || f.id === 'INTERNSHIP_FEE'));
});

test('OCR Engine - handles empty buffer gracefully', async () => {
  const { extractTextFromImage } = require('../engine/ocr');
  const res = await extractTextFromImage(Buffer.alloc(0));
  assert.strictEqual(res.success, false);
  assert.match(res.error, /empty/i);
});

test('OCR Engine - returns helpful error for blank / unreadable image', async () => {
  const { extractTextFromImage } = require('../engine/ocr');
  const fs = require('fs');
  const path = require('path');

  const blankBuf = fs.readFileSync(path.join(__dirname, 'fixtures/blank.png'));
  const res = await extractTextFromImage(blankBuf);
  assert.strictEqual(res.success, false);
  assert.match(res.error, /could not extract readable text/i);
});


