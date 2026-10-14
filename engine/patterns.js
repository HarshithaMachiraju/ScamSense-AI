/**
 * ScamSense AI - Heuristic Pattern Library
 * Tailored for students, freshers, job seekers, and families.
 */

const RED_FLAG_PATTERNS = [
  // 1. Internship & Job Offer Advance Fee Scams
  {
    id: 'INTERNSHIP_FEE',
    category: 'Advance Fee Demanded',
    name: 'Internship / Job Training or Registration Fee',
    regex: /(?:pay|send|transfer|deposit|charge|fee)[\s\S]{0,60}?(?:(?:registration|security\s*deposit|laptop|training|kit|uniform|offer\s*letter|slot\s*booking|background\s*verification|processing)[\s\S]{0,60}?(?:rs\.?|inr|₹|\$)?\s*\d+|(?:rs\.?|inr|₹|\$)?\s*\d+[\s\S]{0,60}?(?:registration|security\s*deposit|laptop|training|kit|uniform|offer\s*letter|slot\s*booking|background\s*verification|processing))/i,
    weight: 42,
    severity: 'critical',
    explanation: 'Legitimate employers and reputable internships never charge candidates fees for registration, laptop deposits, training kits, or offer letter issuance.',
    safeNextStep: 'Never pay any amount to secure a job or internship. Reputable employers provide equipment and training free of charge. Verify on the company careers portal or campus placement cell.'
  },
  {
    id: 'INTERNSHIP_SECURITY_DEPOSIT',
    category: 'Advance Fee Demanded',
    name: 'Refundable Security Deposit Demand',
    regex: /(?:refundable|caution)\s*(?:security\s*)?deposit[\s\S]{0,60}?(?:rs\.?|inr|₹|\$)?\s*\d+|(?:rs\.?|inr|₹|\$)?\s*\d+[\s\S]{0,60}?(?:refundable|caution)\s*(?:security\s*)?deposit/i,
    weight: 38,
    severity: 'critical',
    explanation: 'Scammers frequently claim fees are "100% refundable" to disarm your skepticism before disappearing with your money.',
    safeNextStep: 'Refuse all payment requests. Once transferred via UPI or bank, advance fee scam payments are almost impossible to recover.'
  },
  {
    id: 'UNOFFICIAL_HIRING_CHANNEL',
    category: 'Impersonation & Unofficial Channels',
    name: 'Corporate Offer via Free Public Email or Telegram/WhatsApp',
    regex: /(?:selected|hired|interview|hr|careers|offer)\b[\s\S]{0,120}?(?:@gmail\.com|@yahoo\.com|@outlook\.com|@hotmail\.com|telegram\s*(?:channel|id|group)?\s*[:@]|wa\.me\/|hr\s*whatsapp)/i,
    weight: 28,
    severity: 'high',
    explanation: 'Reputable corporate recruiters from tech companies never use personal Gmail accounts or direct applicants to anonymous Telegram or WhatsApp chats for official job placements.',
    safeNextStep: 'Check the sender domain. Legitimate hiring representatives always contact you from verified company email domains (e.g., @google.com, @microsoft.com).'
  },
  {
    id: 'SELECTION_WITHOUT_INTERVIEW',
    category: 'Unrealistic Promises',
    name: 'Job Selection Without Evaluation',
    regex: /(?:selected|shortlisted|approved)\b[\s\S]{0,60}?(?:without|no)\s*(?:any\s*)?(?:technical\s*)?(?:interview|test|screening|assessment|exam)/i,
    weight: 32,
    severity: 'high',
    explanation: 'Claiming you have been selected for a high-paying role without any technical interview, phone screen, or assessment is a hallmark of employment fraud.',
    safeNextStep: 'Be skeptical of unexpected job offers. Real organizations follow structured recruitment and evaluation procedures.'
  },

  // 2. Scholarship & Educational Grant Scams
  {
    id: 'SCHOLARSHIP_PROCESSING_FEE',
    category: 'Advance Fee Demanded',
    name: 'Scholarship / Grant Disbursement Fee',
    regex: /(?:scholarship|grant|fund|award|fellowship)\b[\s\S]{0,120}?(?:(?:disbursement|clearance|processing|claim|tax)\s*(?:charge|fee|amount|cost)[\s\S]{0,40}?(?:rs\.?|inr|₹|\$)?\s*\d+|(?:rs\.?|inr|₹|\$)?\s*\d+[\s\S]{0,40}?(?:disbursement|clearance|processing|claim|tax)\s*(?:charge|fee|amount|cost))/i,
    weight: 42,
    severity: 'critical',
    explanation: 'Legitimate scholarships are awarded to provide financial support; they will never ask you to pay an upfront "disbursement" or "claim" fee to release your funds.',
    safeNextStep: 'Never pay to receive a scholarship. Check the National Scholarship Portal (scholarships.gov.in) or your university registrar to verify genuine schemes.'
  },
  {
    id: 'SENSITIVE_DOCS_OVER_CHAT',
    category: 'Identity Theft Risk',
    name: 'Demanding Sensitive Identity Documents via Unverified Chat',
    regex: /(?:send|share|upload|whatsapp)\b[\s\S]{0,60}?(?:aadhaar|pan\s*card|passport|voter\s*id|bank\s*(?:passbook|statement))[\s\S]{0,60}?(?:whatsapp|telegram|number|chat|email)/i,
    weight: 36,
    severity: 'critical',
    explanation: 'Collecting Aadhaar, PAN card copies, or bank passbook photos over WhatsApp or Telegram exposes you to synthetic identity theft, unauthorized loan applications, and SIM-swap fraud.',
    safeNextStep: 'Do not share identity documents through messaging apps. Only submit documents via official, encrypted institutional portals with verified security certificates.'
  },

  // 3. Credential Harvesting & Account Takeover
  {
    id: 'OTP_PASSWORD_REQUEST',
    category: 'Credential Harvesting',
    name: 'Request for OTP, PIN, or Password',
    regex: /(?:share|tell|send|enter|verify|provide)\s*(?:your)?\s*(?:bank\s*otp|account\s*otp|login\s*otp|card\s*otp|mpin|upi\s*pin|atm\s*pin|cvv|net\s*banking\s*password|(?:secret\s*)?otp\b(?![\s\S]{0,40}?(?:delivery\s*associate|receiving\s*(?:the)?\s*package)))/i,
    weight: 45,
    severity: 'critical',
    explanation: 'No bank, service provider, or educational body will ever ask you to share your OTP, UPI PIN, or password. Any message asking for these is an immediate scam.',
    safeNextStep: 'NEVER share OTPs or PINs with anyone under any circumstances, even if they claim to be bank officials, police officers, or support agents.'
  },
  {
    id: 'KYC_PAN_EXPIRY_THREAT',
    category: 'Urgency & Intimidation',
    name: 'Imminent Account / KYC Suspension Threat',
    regex: /(?:account|debit\s*card|sim|pan|kyc)\b[\s\S]{0,60}?(?:suspended|blocked|deactivated|closed|frozen)[\s\S]{0,60}?(?:today|within\s*\d+\s*(?:hours|hrs|mins)|immediately|urgently|24\s*hours)/i,
    weight: 38,
    severity: 'critical',
    explanation: 'Scammers manufacture artificial panic with threats of immediate account suspension to pressure victims into clicking malicious links without thinking.',
    safeNextStep: 'Do not panic or click any link. Log into your official mobile banking app or visit your local branch to check your genuine account standing.'
  },

  // 4. UPI Reversal & Payment Tricks
  {
    id: 'UPI_ENTER_PIN_TO_RECEIVE',
    category: 'Payment Deception',
    name: 'UPI PIN Prompt to "Receive" Money',
    regex: /(?:enter|type|input)\s*(?:your)?\s*(?:upi\s*pin|mpin)\s*(?:to)?\s*(?:receive|credit|accept|claim)\s*(?:money|payment|cashback|refund)/i,
    weight: 45,
    severity: 'critical',
    explanation: 'Fundamental rule of UPI: You ONLY enter your UPI PIN to SEND money, NEVER to receive money. If a prompt asks for your PIN, money will be deducted from your account.',
    safeNextStep: 'Decline the request immediately. Entering your UPI PIN authorizes a withdrawal from your bank account.'
  },
  {
    id: 'LOTTERY_PRIZE_ADVANCE_TAX',
    category: 'Advance Fee Demanded',
    name: 'Prize / Lottery / Gift Winning Advance Tax',
    regex: /(?:won|winner|awarded|lucky\s*draw|kbc|lottery)\b[\s\S]{0,80}?(?:pay|deposit|transfer|charge|tax|gst)\s*(?:rs\.?|inr|₹|\$)?\s*\d+/i,
    weight: 40,
    severity: 'critical',
    explanation: 'Unsolicited lottery winnings or prize notifications that demand a "tax" or "clearance fee" before delivery are 100% fraudulent advance fee scams.',
    safeNextStep: 'Delete the message. You cannot win a lottery or contest you never entered.'
  },

  // 5. Task Fraud & Daily Part-Time Scams
  {
    id: 'TASK_FRAUD_LIKE_MAPS',
    category: 'Task Fraud / Ponzi Scheme',
    name: 'Part-Time Work-From-Home Task Scam',
    regex: /(?:earn|daily\s*income|earn\s*daily|part\s*time\s*job)[\s\S]{0,120}?(?:liking\s*youtube|rating|youtube\s*videos|google\s*maps|hotel\s*review|prepaid\s*task|telegram)/i,
    weight: 38,
    severity: 'high',
    explanation: 'Promises of easy daily income (₹2,000–₹8,000) for simple actions like liking YouTube videos or rating Google Maps are part-time task frauds designed to trap you in prepaid crypto deposits.',
    safeNextStep: 'Ignore and report. These schemes pay small sums initially before demanding thousands of rupees in "prepaid merchant tasks" that can never be withdrawn.'
  },

  // 6. Suspicious URLs & Spoofed Domains
  {
    id: 'SUSPICIOUS_SHORTENER_LINK',
    category: 'Suspicious Links',
    name: 'Obfuscated or Shortened URL in Critical Message',
    regex: /https?:\/\/(?:bit\.ly|tinyurl\.com|is\.gd|t\.co|rb\.gy|cutt\.ly|shorturl\.at|ow\.ly|v\.gd)\/[a-zA-Z0-9_-]+/i,
    weight: 24,
    severity: 'medium',
    explanation: 'URL shorteners hide the real destination website. Scammers use them to disguise phishing domains, fake payment portals, and credential harvesters.',
    safeNextStep: 'Do not click shortened URLs in unsolicited messages. Expand them with a URL verification tool or navigate to official websites directly.'
  },
  {
    id: 'SUSPICIOUS_TLD_OR_IP',
    category: 'Suspicious Links',
    name: 'Suspicious Domain Extension or Raw IP Link',
    regex: /https?:\/\/(?:(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9-]+\.(?:top|xyz|club|work|icu|buzz|site|online|cfd|gq|ml|tk|monster|click))\b/i,
    weight: 34,
    severity: 'critical',
    explanation: 'Institutions and reputable organizations never host banking, employment, or academic services on cheap, high-risk top-level domains like .top, .xyz, or raw IP addresses.',
    safeNextStep: 'Inspect the address bar carefully. Genuine banking and corporate portals use established domains (e.g., .com, .org, .edu, .ac.in, .gov.in).'
  },
  {
    id: 'APK_DOWNLOAD_LINK',
    category: 'Malware Danger',
    name: 'Direct APK File or App Sideloading Prompt',
    regex: /(?:download|install|update)\b[\s\S]{0,60}?(?:\.apk|remote\s*support|anydesk|teamviewer|rustdesk|quicksupport)/i,
    weight: 42,
    severity: 'critical',
    explanation: 'Messages instructing you to download an APK file or install remote desktop software allow fraudsters to remotely control your phone and intercept SMS OTPs.',
    safeNextStep: 'Never install APK files sent via SMS or WhatsApp, and never install remote screen-sharing tools on instructions from unverified callers.'
  },

  // 7. Extreme Coercion / "Digital Arrest" & Legal Threats
  {
    id: 'LEGAL_ARREST_THREAT',
    category: 'Urgency & Intimidation',
    name: 'Digital Arrest / Police / Customs Threat',
    regex: /(?:cbi|police|customs|narcotics|ed\b|trai|court|fir|warrant)\b[\s\S]{0,80}?(?:arrest|parcel|drugs|illegal|penalty|settlement|skype|transfer)/i,
    weight: 44,
    severity: 'critical',
    explanation: 'Law enforcement agencies, customs, and courts never conduct "digital arrests" via video call or demand money transfers to clear legal investigations.',
    safeNextStep: 'Stay calm. Hang up immediately and report the intimidation to the National Cyber Crime Helpline at 1930 or cybercrime.gov.in.'
  },

  // 8. General High Pressure Urgency
  {
    id: 'HIGH_PRESSURE_URGENCY',
    category: 'Urgency & Intimidation',
    name: 'Artificial Time Pressure Tactics',
    regex: /(?:urgent|immediately|within\s*(?:10|15|30|60)\s*(?:mins|minutes)|in\s*2\s*hours|within\s*2\s*hours|before\s*[45]\s*pm\s*today|valid\s*only\s*until\s*[45]:00\s*pm|last\s*chance|offer\s*expires\s*soon)/i,
    weight: 20,
    severity: 'medium',
    explanation: 'Artificial urgency is a psychological coercion technique designed to short-circuit analytical thinking and force hurried decisions.',
    safeNextStep: 'Slow down. Legitimate organizations provide reasonable timeframes for administrative and financial decisions.'
  }
];

// Indicators of Genuine or Legitimate Messages (Protective factors)
const PROTECTIVE_PATTERNS = [
  {
    id: 'SECURITY_NEVER_ASKS_OTP',
    name: 'Standard Security Reminder ("Never ask for OTP / Fees")',
    regex: /(?:never|will\s*not|do\s*not)\s*(?:ask\s*for|share|reveal|disclose)[\s\S]{0,60}?(?:otp|pin|password|cvv|account\s*details|extra\s*delivery\s*fees|delivery\s*fees|banking\s*details)/i,
    reduction: 25,
    explanation: 'Contains standard enterprise security disclaimer advising recipients to protect confidential details.'
  },
  {
    id: 'NO_FEES_EXPLICIT',
    name: 'Explicit No-Fee Confirmation',
    regex: /(?:no\s*(?:fee|fees|charges|payment|cost)\s*(?:is|are)?\s*required|free\s*of\s*cost|strictly\s*free|there\s*are\s*no\s*fees)/i,
    reduction: 30,
    explanation: 'Explicitly states that no fees or payments are required, characteristic of legitimate institutional placement drives.'
  },
  {
    id: 'OFFICIAL_APP_INSTRUCTION',
    name: 'Directs User to Official In-App Flow',
    regex: /(?:in\s*the\s*official|open\s*your\s*(?:bank|amazon|flipkart|official)\s*app|visit\s*(?:official\s*portal|campus|branch|placement\s*office))/i,
    reduction: 20,
    explanation: 'Advises recipients to verify within the official application or visit an official campus/branch office directly.'
  },
  {
    id: 'MASKED_ACCOUNT_OR_CARD',
    name: 'Masked Account / Order Syntax',
    regex: /(?:account|a\/c|card|order)\s*(?:ending\s*(?:with|in)|no\.?|#)?\s*(?:x{3,}|[x*]{2,}\d{3,4}|#\d+-\d+-\d+|\b\d{4}\b)/i,
    reduction: 15,
    explanation: 'Uses standard enterprise data privacy masking (e.g. XXXX1234, #402-8819201) rather than demanding sensitive numbers.'
  }
];

// Rich Demo Presets for Hackathon demonstration
const DEMO_PRESETS = [
  {
    id: 'demo-internship-scam',
    title: 'Suspicious Internship Fee Demand',
    badge: 'High Risk Example',
    category: 'Internship / Employment Scam',
    description: 'Targeted scam targeting college students with fake selection letters demanding laptop and training kit deposits.',
    content: `Subject: CONGRATULATIONS! Selected for Google Summer Virtual Internship 2026

Dear Student,

We are pleased to inform you that your profile has been selected for the Google Summer Virtual Internship 2026 (Stipend: Rs 45,000/month) without any technical interview!

To confirm your slot and receive your Google Workstation Laptop, ID badge, and training kit, you must pay a 100% refundable security deposit of Rs 1,999 within 2 hours.

Pay immediately via UPI to: hr-google-onboarding@okaxis
Send payment screenshot to our HR WhatsApp at +91-98765-XXXXX along with your Aadhaar card photo.

Hurry! Slots valid only until 5:00 PM today.
Regards,
HR Talent Acquisition Team`
  },
  {
    id: 'demo-scholarship-fraud',
    title: 'Fake Scholarship Award Processing Fee',
    badge: 'High Risk Example',
    category: 'Scholarship / Grant Scam',
    description: 'Deceptive educational scholarship notification asking for processing charges and Aadhaar documents.',
    content: `National Merit Education Scholarship Fund (Govt Approved)

Dear Applicant,
Congratulations! You have been awarded Rs 75,000 for Higher Academic Excellence 2026!

To release your disbursement code and initiate direct bank transfer, pay mandatory clearance fee of Rs 850 before 4 PM today.

Click link to pay: http://scholarship-disbursement.top/claim
Send your Aadhaar copy, PAN card, and bank passbook photo on WhatsApp to activate disbursement. Do not ignore.`
  },
  {
    id: 'demo-kyc-suspension',
    title: 'Urgent Bank / KYC Suspension Phishing',
    badge: 'High Risk Example',
    category: 'Banking / Phishing Phobia',
    description: 'Panic-inducing message claiming account deactivation with a spoofed high-risk TLD link.',
    content: `Dear SBI Customer,
Your A/C ending with 4821 is suspended today due to pending PAN KYC verification!
Your debit card and UPI transactions have been blocked.

To unblock immediately within 24 hours, update your KYC at:
http://sbi-pan-update.xyz/verify

Failing to do so will result in permanent account closure and penalty.
State Bank of India`
  },
  {
    id: 'demo-task-fraud',
    title: 'Part-Time Telegram Task & Rating Fraud',
    badge: 'Suspicious Example',
    category: 'Task / Part-Time Job Fraud',
    description: 'Work from home scheme promising daily payout for liking videos or rating hotels.',
    content: `PART TIME JOB OPPORTUNITY FOR STUDENTS!
Earn Rs 3,000 to Rs 8,000 daily from your phone.
Work: Just liking YouTube videos and rating Google Maps hotels.
- No interview needed
- No prior experience required
- Daily payout via UPI

Join our official VIP Telegram channel @DailyIncomeHub now to claim your first Rs 500 bonus! Valid for first 50 applicants only.`
  },
  {
    id: 'demo-legit-campus-placement',
    title: 'Legitimate Campus Placement Drive Notice',
    badge: 'Lower Concern Baseline',
    category: 'Authentic Campus Notice',
    description: 'Real-world university placement cell announcement following standard institutional practices.',
    content: `Notice from Training & Placement Cell - Campus Recruitment 2026

Dear Final Year Students,
Microsoft will be conducting an on-campus preliminary coding evaluation tomorrow at 10:00 AM in Computer Lab 3.

Eligibility: Computer Science and IT students with CGPA 7.5 and above.
Requirements: Bring your physical college ID card, updated resume, and notebook.

Please note: The university placement drive is strictly free of cost. There are no fees or payments required for placement participation. Do not pay any individual claiming to represent recruiters.

Training & Placement Office
Dean of Student Affairs`
  },
  {
    id: 'demo-legit-delivery-alert',
    title: 'Legitimate Delivery & Transaction Baseline',
    badge: 'Lower Concern Baseline',
    category: 'Authentic Enterprise Alert',
    description: 'Authentic transactional alert with standard security disclaimers and masked information.',
    content: `Amazon Order Update:
Your delivery for order #402-8819201-1928192 with item 'Electronics Study Kit' is out for delivery today and will arrive before 4:00 PM.
Please share delivery OTP 8391 with the delivery associate ONLY at the time of receiving the package.

Amazon delivery associates will never ask for extra delivery fees or bank account details. Track your package securely in the official Amazon app.`
  }
];

module.exports = {
  RED_FLAG_PATTERNS,
  PROTECTIVE_PATTERNS,
  DEMO_PRESETS
};
