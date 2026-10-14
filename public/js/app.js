/**
 * ScamSense AI - Client Application Logic
 * Interactive dashboard, API communication, preset handling, and comparison mode.
 */

// Embedded fallback presets in case network fetch fails
const CLIENT_PRESETS = {
  'demo-internship-scam': {
    title: 'Suspicious Internship Fee Demand',
    content: `Subject: CONGRATULATIONS! Selected for Google Summer Virtual Internship 2026\n\nDear Student,\n\nWe are pleased to inform you that your profile has been selected for the Google Summer Virtual Internship 2026 (Stipend: Rs 45,000/month) without any technical interview!\n\nTo confirm your slot and receive your Google Workstation Laptop, ID badge, and training kit, you must pay a 100% refundable security deposit of Rs 1,999 within 2 hours.\n\nPay immediately via UPI to: hr-google-onboarding@okaxis\nSend payment screenshot to our HR WhatsApp at +91-98765-XXXXX along with your Aadhaar card photo.\n\nHurry! Slots valid only until 5:00 PM today.\nRegards,\nHR Talent Acquisition Team`
  },
  'demo-scholarship-fraud': {
    title: 'Fake Scholarship Award Processing Fee',
    content: `National Merit Education Scholarship Fund (Govt Approved)\n\nDear Applicant,\nCongratulations! You have been awarded Rs 75,000 for Higher Academic Excellence 2026!\n\nTo release your disbursement code and initiate direct bank transfer, pay mandatory clearance fee of Rs 850 before 4 PM today.\n\nClick link to pay: http://scholarship-disbursement.top/claim\nSend your Aadhaar copy, PAN card, and bank passbook photo on WhatsApp to activate disbursement. Do not ignore.`
  },
  'demo-kyc-suspension': {
    title: 'Urgent Bank / KYC Suspension Phishing',
    content: `Dear SBI Customer,\nYour A/C ending with 4821 is suspended today due to pending PAN KYC verification!\nYour debit card and UPI transactions have been blocked.\n\nTo unblock immediately within 24 hours, update your KYC at:\nhttp://sbi-pan-update.xyz/verify\n\nFailing to do so will result in permanent account closure and penalty.\nState Bank of India`
  },
  'demo-task-fraud': {
    title: 'Part-Time Telegram Task & Rating Fraud',
    content: `PART TIME JOB OPPORTUNITY FOR STUDENTS!\nEarn Rs 3,000 to Rs 8,000 daily from your phone.\nWork: Just liking YouTube videos and rating Google Maps hotels.\n- No interview needed\n- No prior experience required\n- Daily payout via UPI\n\nJoin our official VIP Telegram channel @DailyIncomeHub now to claim your first Rs 500 bonus! Valid for first 50 applicants only.`
  },
  'demo-legit-campus-placement': {
    title: 'Legitimate Campus Placement Drive Notice',
    content: `Notice from Training & Placement Cell - Campus Recruitment 2026\n\nDear Final Year Students,\nMicrosoft will be conducting an on-campus preliminary coding evaluation tomorrow at 10:00 AM in Computer Lab 3.\n\nEligibility: Computer Science and IT students with CGPA 7.5 and above.\nRequirements: Bring your physical college ID card, updated resume, and notebook.\n\nPlease note: The university placement drive is strictly free of cost. There are no fees or payments required for placement participation. Do not pay any individual claiming to represent recruiters.\n\nTraining & Placement Office\nDean of Student Affairs`
  },
  'demo-legit-delivery-alert': {
    title: 'Legitimate Delivery & Transaction Baseline',
    content: `Amazon Order Update:\nYour delivery for order #402-8819201-1928192 with item 'Electronics Study Kit' is out for delivery today and will arrive before 4:00 PM.\nPlease share delivery OTP 8391 with the delivery associate ONLY at the time of receiving the package.\n\nAmazon delivery associates will never ask for extra delivery fees or bank account details. Track your package securely in the official Amazon app.`
  }
};

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements - Single Analysis
  const messageInput = document.getElementById('message-input');
  const btnAnalyze = document.getElementById('btn-analyze');
  const btnAnalyzeText = document.getElementById('btn-analyze-text');
  const btnClear = document.getElementById('btn-clear-input');
  const btnPaste = document.getElementById('btn-paste-clip');
  const charCountEl = document.getElementById('char-count');
  const wordCountEl = document.getElementById('word-count');
  const validationBanner = document.getElementById('validation-banner');
  const validationMessage = document.getElementById('validation-message');

  // Input Mode Elements (Text vs Image OCR)
  const modeTextBtn = document.getElementById('mode-text-btn');
  const modeImageBtn = document.getElementById('mode-image-btn');
  const inputWrapperText = document.getElementById('input-wrapper-text');
  const inputWrapperImage = document.getElementById('input-wrapper-image');
  const imageDropzone = document.getElementById('image-dropzone');
  const imageFileInput = document.getElementById('image-file-input');
  const imagePreviewCard = document.getElementById('image-preview-card');
  const imagePreviewThumb = document.getElementById('image-preview-thumb');
  const imagePreviewName = document.getElementById('image-preview-name');
  const imagePreviewSize = document.getElementById('image-preview-size');
  const btnRemoveImage = document.getElementById('btn-remove-image');

  // OCR Results Banner Elements
  const ocrExtractedBanner = document.getElementById('ocr-extracted-banner');
  const ocrConfidencePill = document.getElementById('ocr-confidence-pill');
  const ocrExtractedPreview = document.getElementById('ocr-extracted-preview');
  const btnCopyOcrText = document.getElementById('btn-copy-ocr-text');
  
  // Results Elements
  const resultsSection = document.getElementById('results-section');
  const riskCard = document.getElementById('risk-card');
  const gaugeFill = document.getElementById('gauge-fill');
  const gaugeNumber = document.getElementById('gauge-number');
  const riskCategoryText = document.getElementById('risk-category-text');
  const riskIcon = document.getElementById('risk-icon');
  const riskSummaryText = document.getElementById('risk-summary-text');
  const metricFindings = document.getElementById('metric-findings');
  const metricProtective = document.getElementById('metric-protective');
  const metricTime = document.getElementById('metric-time');
  const highlightViewer = document.getElementById('highlight-viewer');
  const findingsContainer = document.getElementById('findings-container');
  const protectiveBox = document.getElementById('protective-box');
  const protectiveList = document.getElementById('protective-list');
  const nextStepsContainer = document.getElementById('next-steps-container');
  const btnJumpNextSteps = document.getElementById('btn-jump-nextsteps');

  // DOM Elements - Comparison Mode
  const compareInputA = document.getElementById('compare-input-a');
  const compareInputB = document.getElementById('compare-input-b');
  const btnRunCompare = document.getElementById('btn-run-compare');
  const btnLoadDemoCompare = document.getElementById('btn-load-demo-comparison');
  const compareValidationBanner = document.getElementById('compare-validation-banner');
  const compareValidationMessage = document.getElementById('compare-validation-message');
  const comparisonResults = document.getElementById('comparison-results');
  const verdictDescription = document.getElementById('verdict-description');
  const compScoreA = document.getElementById('comp-score-a');
  const compFindingsA = document.getElementById('comp-findings-a');
  const compCardA = document.getElementById('comp-card-a');
  const compScoreB = document.getElementById('comp-score-b');
  const compFindingsB = document.getElementById('comp-findings-b');
  const compCardB = document.getElementById('comp-card-b');

  // Tabs Elements
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  // 1. Tab Switching Logic
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('aria-controls');

      tabBtns.forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
        b.setAttribute('tabindex', '-1');
      });

      tabContents.forEach(content => {
        content.classList.remove('active');
      });

      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      btn.setAttribute('tabindex', '0');

      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add('active');
      }
    });
  });

  // WAI-ARIA Keyboard Navigation for Tabs (Left / Right / Home / End)
  const tablist = document.querySelector('.tabs-navigation');
  if (tablist) {
    tablist.addEventListener('keydown', (e) => {
      const tabs = Array.from(tabBtns);
      const currentIndex = tabs.findIndex(tab => tab.classList.contains('active'));
      if (currentIndex === -1) return;

      let targetIndex = -1;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        e.preventDefault();
        targetIndex = (currentIndex + 1) % tabs.length;
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        e.preventDefault();
        targetIndex = (currentIndex - 1 + tabs.length) % tabs.length;
      } else if (e.key === 'Home') {
        e.preventDefault();
        targetIndex = 0;
      } else if (e.key === 'End') {
        e.preventDefault();
        targetIndex = tabs.length - 1;
      }

      if (targetIndex !== -1) {
        tabs[targetIndex].focus();
        tabs[targetIndex].click();
      }
    });
  }

  // 2. Character & Word Counter
  function updateStats() {
    const text = messageInput.value;
    const chars = text.length;
    const words = text.trim() ? text.trim().split(/\s+/).length : 0;
    charCountEl.textContent = `${chars} character${chars === 1 ? '' : 's'}`;
    wordCountEl.textContent = `${words} word${words === 1 ? '' : 's'}`;
  }

  messageInput.addEventListener('input', () => {
    updateStats();
    hideValidationError();
  });

  // Keyboard shortcut: Ctrl + Enter / Cmd + Enter to Analyze
  messageInput.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      btnAnalyze.click();
    }
  });

  // 3. Clear & Paste Buttons
  btnClear.addEventListener('click', () => {
    messageInput.value = '';
    updateStats();
    hideValidationError();
    resultsSection.classList.remove('visible');
    messageInput.focus();
  });

  btnPaste.addEventListener('click', async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.readText) {
        const text = await navigator.clipboard.readText();
        messageInput.value = text;
        updateStats();
        hideValidationError();
        messageInput.focus();
      } else {
        showValidationError('Clipboard access is restricted by your browser. Please paste using Ctrl+V.');
      }
    } catch {
      showValidationError('Could not access clipboard directly. Please press Ctrl+V to paste.');
    }
  });

  // 4. Demo Preset Chips Click
  const presetChips = document.querySelectorAll('.preset-chip');
  presetChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const presetKey = chip.getAttribute('data-preset');
      const presetData = CLIENT_PRESETS[presetKey];
      if (presetData) {
        messageInput.value = presetData.content;
        updateStats();
        hideValidationError();
        // Visual indicator on clicked preset
        presetChips.forEach(c => c.style.borderColor = '');
        chip.style.borderColor = '#38bdf8';
        messageInput.focus();
        messageInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });
  });

  // 5. Validation Helpers
  function showValidationError(msg) {
    validationMessage.textContent = msg;
    validationBanner.style.display = 'flex';
  }

  function hideValidationError() {
    validationBanner.style.display = 'none';
  }

  function showCompareValidationError(msg) {
    compareValidationMessage.textContent = msg;
    compareValidationBanner.style.display = 'flex';
  }

  function hideCompareValidationError() {
    compareValidationBanner.style.display = 'none';
  }

  // 5. Input Mode Switcher Logic (Text vs Image OCR)
  let currentInputMode = 'text'; // 'text' | 'image'
  let selectedImageFile = null;
  let previewUrl = null;

  function switchMode(newMode) {
    currentInputMode = newMode;
    hideValidationError();

    if (newMode === 'text') {
      if (modeTextBtn) {
        modeTextBtn.classList.add('active');
        modeTextBtn.setAttribute('aria-selected', 'true');
      }
      if (modeImageBtn) {
        modeImageBtn.classList.remove('active');
        modeImageBtn.setAttribute('aria-selected', 'false');
      }
      if (inputWrapperText) inputWrapperText.style.display = 'block';
      if (inputWrapperImage) inputWrapperImage.style.display = 'none';
      if (btnAnalyzeText) btnAnalyzeText.textContent = '🛡️ Analyze Message';
    } else {
      if (modeImageBtn) {
        modeImageBtn.classList.add('active');
        modeImageBtn.setAttribute('aria-selected', 'true');
      }
      if (modeTextBtn) {
        modeTextBtn.classList.remove('active');
        modeTextBtn.setAttribute('aria-selected', 'false');
      }
      if (inputWrapperText) inputWrapperText.style.display = 'none';
      if (inputWrapperImage) inputWrapperImage.style.display = 'block';
      if (btnAnalyzeText) btnAnalyzeText.textContent = '🔍 Scan Image with OCR';
    }
  }

  if (modeTextBtn && modeImageBtn) {
    modeTextBtn.addEventListener('click', () => switchMode('text'));
    modeImageBtn.addEventListener('click', () => switchMode('image'));
  }

  // Image File Handling & Preview
  function handleImageFile(file) {
    if (!file) return;

    const validTypes = ['image/jpeg', 'image/jpg', 'image/png'];
    const fileType = (file.type || '').toLowerCase();
    const fileName = (file.name || '').toLowerCase();
    const isExtensionValid = fileName.endsWith('.png') || fileName.endsWith('.jpg') || fileName.endsWith('.jpeg');

    if (!validTypes.includes(fileType) && !isExtensionValid) {
      showValidationError('Unsupported file type. Please upload a JPG, JPEG, or PNG screenshot.');
      return;
    }

    const maxSize = 5 * 1024 * 1024; // 5 MB
    if (file.size > maxSize) {
      showValidationError('Image file exceeds the 5 MB limit. Please choose a smaller screenshot.');
      return;
    }

    selectedImageFile = file;
    hideValidationError();

    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
    }
    previewUrl = URL.createObjectURL(file);
    if (imagePreviewThumb) imagePreviewThumb.src = previewUrl;
    if (imagePreviewName) imagePreviewName.textContent = file.name;
    if (imagePreviewSize) imagePreviewSize.textContent = formatBytes(file.size);

    if (imageDropzone) imageDropzone.style.display = 'none';
    if (imagePreviewCard) imagePreviewCard.style.display = 'flex';
  }

  function resetImageSelection() {
    selectedImageFile = null;
    if (imageFileInput) imageFileInput.value = '';
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      previewUrl = null;
    }
    if (imagePreviewThumb) imagePreviewThumb.src = '';
    if (imagePreviewCard) imagePreviewCard.style.display = 'none';
    if (imageDropzone) imageDropzone.style.display = 'flex';
    hideValidationError();
  }

  if (btnRemoveImage) {
    btnRemoveImage.addEventListener('click', resetImageSelection);
  }

  if (imageDropzone && imageFileInput) {
    imageDropzone.addEventListener('click', () => imageFileInput.click());
    imageDropzone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        imageFileInput.click();
      }
    });

    imageFileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleImageFile(e.target.files[0]);
      }
    });

    // Drag and drop events
    ['dragenter', 'dragover'].forEach(eventName => {
      imageDropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        imageDropzone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      imageDropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        imageDropzone.classList.remove('dragover');
      });
    });

    imageDropzone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      if (dt && dt.files && dt.files[0]) {
        handleImageFile(dt.files[0]);
      }
    });
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    const kb = (bytes / 1024).toFixed(1);
    if (kb < 1024) return kb + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  }

  // Copy OCR Text to Textarea
  if (btnCopyOcrText) {
    btnCopyOcrText.addEventListener('click', () => {
      if (ocrExtractedPreview && ocrExtractedPreview.textContent) {
        messageInput.value = ocrExtractedPreview.textContent;
        updateStats();
        switchMode('text');
        messageInput.focus();
        messageInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });
  }

  // 6. Analyze Action (Handles both Text and Image OCR)
  btnAnalyze.addEventListener('click', async () => {
    if (currentInputMode === 'text') {
      const rawText = messageInput.value;
      
      // Client-side validation check
      if (!rawText || !rawText.trim()) {
        showValidationError('Please enter or paste a message to analyze.');
        messageInput.focus();
        return;
      }

      if (rawText.trim().length < 5) {
        showValidationError('Message snippet is too short (minimum 5 characters). Please paste the full text.');
        messageInput.focus();
        return;
      }

      hideValidationError();
      setLoadingState(true, '🛡️ Analyzing Message...');

      try {
        const response = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: rawText })
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
          showValidationError(data.error || 'Failed to analyze message. Please try again.');
          return;
        }

        renderAnalysisResults(data);
      } catch (err) {
        console.error('Fetch error:', err);
        showValidationError('Unable to connect to analysis server. Please check your local connection.');
      } finally {
        setLoadingState(false);
      }
    } else {
      // Image OCR mode
      if (!selectedImageFile) {
        showValidationError('Please select or drag & drop a screenshot to analyze.');
        return;
      }

      hideValidationError();
      setLoadingState(true, '🔍 Scanning Screenshot with OCR...');

      try {
        const formData = new FormData();
        formData.append('image', selectedImageFile);

        const response = await fetch('/api/analyze-image', {
          method: 'POST',
          body: formData
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
          showValidationError(data.error || 'Could not extract readable text from this screenshot. Please try a clearer screenshot or paste the text manually.');
          return;
        }

        renderAnalysisResults(data);
      } catch (err) {
        console.error('Image analysis error:', err);
        showValidationError('Error uploading or processing screenshot. Please check server connection.');
      } finally {
        setLoadingState(false);
      }
    }
  });

  function setLoadingState(isLoading, customText) {
    if (isLoading) {
      btnAnalyze.classList.add('loading');
      btnAnalyze.disabled = true;
      if (btnAnalyzeText && customText) {
        btnAnalyzeText.textContent = customText;
      }
    } else {
      btnAnalyze.classList.remove('loading');
      btnAnalyze.disabled = false;
      if (btnAnalyzeText) {
        btnAnalyzeText.textContent = currentInputMode === 'text' ? '🛡️ Analyze Message' : '🔍 Scan Image with OCR';
      }
    }
  }

  // 7. Render Analysis Results
  function renderAnalysisResults(data) {
    const {
      riskScore,
      riskCategory,
      riskSummary,
      findings,
      protectiveSignals,
      safeNextSteps,
      highlightedHtml,
      metrics
    } = data;

    // A. Update Risk Card Theme & Badge
    riskCard.className = 'risk-card';
    if (riskCategory === 'High Risk') {
      riskCard.classList.add('risk-high');
      riskIcon.textContent = '🚨';
      gaugeFill.setAttribute('stroke', '#f43f5e');
    } else if (riskCategory === 'Suspicious') {
      riskCard.classList.add('risk-medium');
      riskIcon.textContent = '⚠️';
      gaugeFill.setAttribute('stroke', '#f59e0b');
    } else {
      riskCard.classList.add('risk-low');
      riskIcon.textContent = '🛡️';
      gaugeFill.setAttribute('stroke', '#10b981');
    }

    riskCategoryText.textContent = riskCategory;
    riskSummaryText.textContent = riskSummary;
    gaugeNumber.textContent = riskScore;

    // Calculate Gauge Circle SVG offset: circumference = 2 * PI * 40 ≈ 251.2
    const circumference = 251.2;
    const offset = circumference - (riskScore / 100) * circumference;
    gaugeFill.style.strokeDashoffset = offset;

    // Metrics
    metricFindings.textContent = `${findings.length} Red Flag${findings.length === 1 ? '' : 's'}`;
    metricProtective.textContent = `${protectiveSignals.length} Protective Signal${protectiveSignals.length === 1 ? '' : 's'}`;
    metricTime.textContent = `Analyzed in ${metrics.durationMs || 4}ms`;

    // OCR Extracted Text Display
    if (data.isOcr && data.extractedText && ocrExtractedBanner) {
      ocrExtractedBanner.style.display = 'block';
      if (ocrExtractedPreview) ocrExtractedPreview.textContent = data.extractedText;
      if (ocrConfidencePill) {
        ocrConfidencePill.textContent = data.ocrConfidence ? `OCR Confidence: ${data.ocrConfidence}%` : 'OCR Extracted';
      }
    } else if (ocrExtractedBanner) {
      ocrExtractedBanner.style.display = 'none';
    }

    // B. Highlighted Viewer
    highlightViewer.innerHTML = highlightedHtml || escapeHtml(messageInput.value);

    // C. Findings List
    findingsContainer.innerHTML = '';
    if (findings.length === 0) {
      findingsContainer.innerHTML = `
        <div style="padding: 1rem; background: rgba(16, 185, 129, 0.08); border-radius: var(--radius-md); color: #a7f3d0; font-size: 0.9rem;">
          ✨ No red flags detected! No advance fee requests, credential harvesting, or spoofed links found in this snippet.
        </div>
      `;
    } else {
      findings.forEach(f => {
        const item = document.createElement('div');
        item.className = `finding-item ${f.severity || 'medium'}`;
        item.innerHTML = `
          <div class="finding-top">
            <span class="finding-category-tag">${escapeHtml(f.category)}</span>
            <span class="finding-severity">Severity: ${escapeHtml(f.severity.toUpperCase())} (+${f.weight} pts)</span>
          </div>
          <div class="finding-title">${escapeHtml(f.name)}</div>
          <div class="finding-quote">"${escapeHtml(f.matchedText)}"</div>
          <div class="finding-explanation">${escapeHtml(f.explanation)}</div>
        `;
        findingsContainer.appendChild(item);
      });
    }

    // D. Protective Signals Box
    if (protectiveSignals && protectiveSignals.length > 0) {
      protectiveBox.style.display = 'block';
      protectiveList.innerHTML = '';
      protectiveSignals.forEach(s => {
        const li = document.createElement('li');
        li.className = 'protective-item';
        li.innerHTML = `<strong>${escapeHtml(s.name)}:</strong> ${escapeHtml(s.explanation)} <span style="color: #6ee7b7;">(-${s.reduction} pts)</span>`;
        protectiveList.appendChild(li);
      });
    } else {
      protectiveBox.style.display = 'none';
    }

    // E. Safe Next Steps
    nextStepsContainer.innerHTML = '';
    safeNextSteps.forEach((step, idx) => {
      const stepCard = document.createElement('div');
      stepCard.className = 'next-step-card';
      stepCard.innerHTML = `
        <div class="step-number">${idx + 1}</div>
        <div class="step-details">
          <h4>${escapeHtml(step.title)}</h4>
          <p>${escapeHtml(step.action)}</p>
        </div>
      `;
      nextStepsContainer.appendChild(stepCard);
    });

    // F. Reveal Results smoothly
    resultsSection.classList.add('visible');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // Smooth jump to next steps
  if (btnJumpNextSteps) {
    btnJumpNextSteps.addEventListener('click', () => {
      const nextStepsSection = document.getElementById('next-steps-section');
      if (nextStepsSection) {
        nextStepsSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });
  }

  // 8. Comparison Mode Implementation
  btnLoadDemoCompare.addEventListener('click', () => {
    compareInputA.value = CLIENT_PRESETS['demo-internship-scam'].content;
    compareInputB.value = CLIENT_PRESETS['demo-legit-campus-placement'].content;
    hideCompareValidationError();
  });

  btnRunCompare.addEventListener('click', async () => {
    const textA = compareInputA.value;
    const textB = compareInputB.value;

    if (!textA || !textA.trim() || !textB || !textB.trim()) {
      showCompareValidationError('Please enter or paste text in both Message A and Message B to perform comparison.');
      return;
    }

    hideCompareValidationError();
    btnRunCompare.classList.add('loading');
    btnRunCompare.disabled = true;

    try {
      const response = await fetch('/api/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messageA: textA, messageB: textB })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        showCompareValidationError(data.error || 'Failed to compare messages.');
        return;
      }

      renderComparisonResults(data);
    } catch (err) {
      console.error('Comparison error:', err);
      showCompareValidationError('Error connecting to server. Please try again.');
    } finally {
      btnRunCompare.classList.remove('loading');
      btnRunCompare.disabled = false;
    }
  });

  function renderComparisonResults(data) {
    const { comparison, messageA, messageB } = data;

    verdictDescription.textContent = comparison.verdict;

    // Card A styling
    compCardA.className = `comp-summary-card ${messageA.badgeColor}`;
    compScoreA.textContent = `Risk Score: ${messageA.riskScore} (${messageA.riskCategory})`;
    compScoreA.style.color = messageA.badgeColor === 'rose' ? '#f43f5e' : (messageA.badgeColor === 'amber' ? '#fbbf24' : '#34d399');
    compFindingsA.innerHTML = messageA.findings.length > 0 
      ? messageA.findings.map(f => `<li><strong>${escapeHtml(f.name)}:</strong> ${escapeHtml(f.matchedText)}</li>`).join('')
      : '<li>No red flags detected.</li>';

    // Card B styling
    compCardB.className = `comp-summary-card ${messageB.badgeColor}`;
    compScoreB.textContent = `Risk Score: ${messageB.riskScore} (${messageB.riskCategory})`;
    compScoreB.style.color = messageB.badgeColor === 'rose' ? '#f43f5e' : (messageB.badgeColor === 'amber' ? '#fbbf24' : '#34d399');
    compFindingsB.innerHTML = messageB.findings.length > 0 
      ? messageB.findings.map(f => `<li><strong>${escapeHtml(f.name)}:</strong> ${escapeHtml(f.matchedText)}</li>`).join('')
      : '<li>No red flags detected.</li>';

    comparisonResults.style.display = 'block';
    comparisonResults.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function escapeHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
});
