# 🛡️ ScamSense AI

> **Explainable Scam Detection for Students & Families**  
> A lightweight, transparent, privacy-first Hackathon MVP designed to protect students, fresh graduates, and families from internship fraud, fake scholarships, KYC suspension panic, task scams, and payment reversal traps.

---

## 🌟 Key Features

1. **Explainable Threat Assessment**:
   - **Risk Tiers**: Clear classification into **Lower Concern**, **Suspicious**, or **High Risk**.
   - **Visual Risk Score Gauge**: 0–100 score with visual circular meter and confidence indicators.
   - **Exact Evidence Highlighting**: Highlights detected deceptive phrases in context with direct explanations of *why* they are hazardous.

2. **Tailored Safe Next Steps**:
   - Dynamic, prioritized action plan tailored specifically to the detected red flags (e.g. *Refuse advance training fees*, *Never share OTPs*, *Verify directly on company portals*, *Report to 1930 / cybercrime.gov.in*).

3. **Comparison Mode (A vs B)**:
   - Side-by-side inspector allowing users to compare two messages (e.g. a suspicious internship offer letter vs. a genuine university placement notice).
   - Generates score differentials and an explicit verdict explaining which message is safer and why.

4. **One-Click Demo Presets**:
   - **Google Internship Fee Scam** (Advance fee for laptop / training kit).
   - **Scholarship Disbursement Scam** (Advance processing charge & Aadhaar harvesting).
   - **Bank / KYC Suspension Alert** (Panic threat with spoofed `.xyz` domain link).
   - **Telegram Part-Time Task Fraud** (Daily ₹3k–₹8k for YouTube likes/ratings).
   - **Legitimate Campus Placement Notice** (Free institutional placement baseline).
   - **Legitimate Amazon Delivery Alert** (Masked details with standard security disclaimers).

5. **Student & Family Threat Guide**:
   - Educational breakdown of the most common student scams (Internship caution fees, fake merit awards, "digital arrest" video intimidation, and UPI reversal tricks).

---

## 🔒 Privacy & Safety Principles

- **Transparent Rule-Based Engine (Demo Mode)**: Operates using transparent heuristic intelligence. Does not pretend an external AI API or third-party sender verification was used.
- **Zero Data Retention**: Messages are evaluated **strictly in-memory** on your local machine. No inputs are stored in any database or file.
- **Credential Protection**: The application never asks for or stores OTPs, passwords, Aadhaar numbers, or bank account details.
- **Educational Disclaimer**: Clearly states that risk assessment is an educational advisory tool and not definitive legal proof of fraud or legitimacy.
- **No Fake Data**: No fabricated testimonials or false statistics.

---

## 🚀 Quick Start Guide

### Prerequisites
- **Node.js** (v18.0.0 or higher; tested on Node.js v24.21.0)
- **npm** (v9.0.0 or higher)

### Installation & Launch

1. **Clone or open the project directory**:
   ```bash
   cd ScamSense-AI
   ```

2. **Install dependencies** (Express):
   ```bash
   npm install
   ```

3. **Start the application**:
   ```bash
   npm start
   ```

4. **Open in your browser**:
   Navigate to [http://localhost:3000](http://localhost:3000)

---

## 🧪 Running Automated Tests

ScamSense AI includes a comprehensive test suite using Node's native test runner (`node:test` & `node:assert`).

To run the full test suite:
```bash
npm test
```

### Test Coverage Summary (13/13 Passing):
- ✔ Input validation: Rejects empty, whitespace-only, null, and short snippets.
- ✔ Suspicious internship registration & laptop fee scams (High Risk classification).
- ✔ Advance-fee scholarship disbursement scams & document harvesting (High Risk classification).
- ✔ KYC deactivation panic messages with spoofed high-risk TLDs (High Risk classification).
- ✔ Work-from-home Telegram task frauds (Suspicious / High Risk).
- ✔ Legitimate university placement drive notices (Lower Concern / Safe).
- ✔ Legitimate e-commerce delivery alerts with delivery OTP (Lower Concern / Safe).
- ✔ False-positive resistance: IT security newsletters discussing scams without triggering false alarms.
- ✔ False-positive resistance: Genuine employment offer letters mentioning salary/CTC without upfront fees.
- ✔ Side-by-side comparison mode engine tests.
- ✔ UPI reversal PIN trick deception detection.
- ✔ Digital arrest / law enforcement coercion detection.
- ✔ Comparison mode error handling for invalid or empty inputs.

---

## 📁 Project Architecture

```
ScamSense-AI/
├── engine/
│   ├── analyzer.js        # Core explainable heuristic analysis & scoring engine
│   └── patterns.js        # Security red flags, protective rules, and demo presets
├── public/
│   ├── index.html         # Accessible, responsive HTML5 dashboard
│   ├── css/
│   │   └── style.css      # Vanilla CSS design system (dark cybersecurity theme)
│   └── js/
│       └── app.js         # Interactive client logic, comparison mode, presets
├── test/
│   └── analyzer.test.js   # Automated unit & integration tests
├── server.js              # Express server with security headers & REST API
├── package.json           # Dependencies and test/start scripts
└── README.md              # Project documentation
```

---

## 📞 Emergency Cyber Incident Helplines

- **National Cyber Crime Reporting Portal**: [https://cybercrime.gov.in](https://cybercrime.gov.in)
- **National Cyber Crime Helpline Number**: **1930** (24x7 Citizen Financial Cyber Fraud Reporting)
