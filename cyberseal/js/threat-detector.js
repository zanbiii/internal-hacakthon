/**
 * CyberSeal — Threat Detector
 * Heuristic, fully client-side phishing / fraud analysis for URLs and messages.
 * Exposes window.ThreatDetector.
 */
(function () {
  'use strict';

  const SUSPICIOUS_TLDS = [
    'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'club', 'work',
    'click', 'link', 'buzz', 'icu', 'rest', 'online', 'site', 'live',
    'shop', 'sbs', 'cyou', 'monster', 'cfd', 'vip'
  ];

  // Brands most impersonated in India first, then global ones.
  const BRANDS = [
    'hdfcbank', 'icicibank', 'axisbank', 'kotak', 'paytm', 'phonepe', 'googlepay',
    'irctc', 'indiapost', 'flipkart', 'airtel', 'uidai', 'incometax', 'epfo',
    'npci', 'bhimupi', 'licindia', 'myntra', 'meesho', 'swiggy', 'zomato',
    'bankofbaroda', 'canarabank', 'unionbank', 'yesbank', 'indusind',
    'google', 'paypal', 'amazon', 'facebook', 'microsoft', 'apple', 'netflix',
    'instagram', 'twitter', 'linkedin', 'whatsapp', 'dropbox', 'yahoo', 'outlook'
  ];

  // Brand names too short for substring matching ("sbi" is inside ordinary words).
  const SHORT_BRAND_PATTERNS = [
    { brand: 'sbi', re: /(^|[-.])(online)?sbi($|[-.0-9]|online|yono|card|bank|kyc|reward)/ },
    { brand: 'pnb', re: /(^|[-.])pnb($|[-.0-9]|bank|kyc|reward)/ },
    { brand: 'jio', re: /(^|[-.])(my)?jio($|[-.0-9]|lottery|lucky|recharge|offer)/ },
    { brand: 'bsnl', re: /(^|[-.])bsnl($|[-.0-9]|kyc|recharge|offer)/ }
  ];

  // Genuine Indian government sites always end in .gov.in or .nic.in.
  const GOV_SUFFIXES = ['gov.in', 'nic.in'];
  const GOV_LOOKALIKE = /(gov|sarkar|yojana|uidai|aadhaa?r|incometax|itr-?refund|epfo|pmkisan|pm-kisan|parivahan|e-?challan|passport|digilocker|cowin|trafficpolice|traffic-?fine|npci|rbi-?|sebi)/;

  const SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.cc', 't.ly'
  ];

  const SAFE_DOMAINS = [
    'google.com', 'youtube.com', 'github.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'facebook.com', 'twitter.com', 'x.com', 'linkedin.com',
    'wikipedia.org', 'stackoverflow.com', 'reddit.com', 'netflix.com',
    'instagram.com', 'whatsapp.com', 'vercel.app',
    // India
    'onlinesbi.sbi', 'sbi.co.in', 'sbi', 'hdfcbank.com', 'icicibank.com', 'axisbank.com',
    'kotak.com', 'paytm.com', 'phonepe.com', 'npci.org.in', 'bhimupi.org.in',
    'rbi.org.in', 'irctc.co.in', 'flipkart.com', 'amazon.in', 'airtel.in', 'jio.com',
    'myntra.com', 'swiggy.com', 'zomato.com', 'licindia.in', 'bankofbaroda.in',
    'pnbindia.in', 'canarabank.com', 'unionbankofindia.co.in', 'yesbank.in', 'indusind.com'
  ];

  const PATH_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update', 'confirm', 'signin',
    'banking', 'password', 'credential', 'wallet', 'authenticate'
  ];

  // Public suffixes with two labels, so "evil.co.uk" resolves to "evil" not "co".
  const MULTI_LABEL_SUFFIXES = [
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.in', 'net.in', 'org.in', 'gov.in',
    'ac.in', 'com.au', 'net.au', 'org.au', 'co.jp', 'com.br', 'co.nz', 'com.sg',
    'com.mx', 'co.za'
  ];

  // Cyrillic / Greek characters that render like Latin letters.
  const HOMOGLYPHS = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ԁ': 'd', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w',
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'τ': 't',
    'υ': 'u', 'χ': 'x'
  };

  // Keyword lists cover English, Hinglish (romanised Hindi) and the main Indian scripts:
  // Hindi/Marathi (Devanagari), Bengali, Tamil, Telugu, Kannada, Malayalam, Gujarati, Punjabi, Odia, Urdu.
  const MESSAGE_RULES = {
    urgency: [
      'urgent', 'immediately', 'now', 'asap', 'hurry', 'limited time', 'act now',
      'expire', 'expires', 'expiring', 'deadline', 'right away', "don't delay",
      'last chance', 'final warning', 'today itself', 'tonight',
      // Hinglish
      'turant', 'jaldi', 'aaj hi', 'abhi',
      // Hindi / Marathi
      'तुरंत', 'जल्दी', 'आज ही', 'अंतिम मौका', 'आज रात', 'त्वरित',
      // Bengali, Tamil, Telugu, Kannada, Malayalam, Gujarati, Punjabi, Odia, Urdu
      'অবিলম্বে', 'এখনই', 'உடனடியாக', 'వెంటనే', 'ತಕ್ಷಣ', 'ഉടൻ', 'તાત્કાલિક', 'ਤੁਰੰਤ', 'ତୁରନ୍ତ', 'فوری'
    ],
    fear: [
      'account suspended', 'suspended', 'compromised', 'unauthorized', 'illegal activity',
      'legal action', 'arrested', 'arrest', 'locked', 'terminated', 'violation',
      'hacked', 'blocked', 'seized', 'frozen', 'disconnected', 'deactivated', 'fir',
      // Hinglish
      'khata band', 'account band', 'band ho jayega', 'connection kat', 'giraftar',
      // Hindi / Marathi
      'खाता बंद', 'बंद कर दिया जाएगा', 'ब्लॉक', 'गिरफ्तार', 'कानूनी कार्रवाई', 'काट दिया जाएगा', 'खाते बंद',
      // Regional
      'অ্যাকাউন্ট বন্ধ', 'முடக்கப்படும்', 'ఖాతా బ్లాక్', 'ಖಾತೆ ಬ್ಲಾಕ್', 'അക്കൗണ്ട് ബ്ലോക്ക്', 'ખાતું બંધ', 'ਖਾਤਾ ਬੰਦ', 'اکاؤنٹ بند'
    ],
    personal: [
      'ssn', 'social security', 'password', 'credit card', 'bank account',
      'date of birth', 'pin', 'cvv', 'routing number', 'otp', 'verification code',
      "mother's maiden", 'aadhaar', 'aadhar', 'pan card', 'upi pin', 'atm pin', 'debit card',
      'card number', 'expiry date', 'net banking',
      // Hindi / Marathi
      'ओटीपी', 'पिन', 'आधार', 'पैन कार्ड', 'बैंक खाता', 'पासवर्ड', 'केवाईसी',
      // Regional (OTP / Aadhaar)
      'ওটিপি', 'আধার', 'ஓடிபி', 'ஆதார்', 'ఓటీపీ', 'ఆధార్', 'ಒಟಿಪಿ', 'ಆಧಾರ್', 'ഒടിപി', 'ആധാർ',
      'ઓટીપી', 'આધાર', 'ਓਟੀਪੀ', 'ਆਧਾਰ', 'ଓଟିପି', 'ଆଧାର', 'او ٹی پی'
    ],
    prize: [
      'won', 'winner', 'congratulations', 'prize', 'lottery', 'million',
      'inheritance', 'beneficiary', 'claim your', 'selected for', 'lucky', 'jackpot',
      'lucky draw', 'bumper prize', 'kbc', 'crorepati', 'cashback', 'reward points',
      // Hinglish
      'inaam', 'badhai ho', 'lottery lagi',
      // Hindi / Marathi
      'लॉटरी', 'इनाम', 'बधाई हो', 'करोड़पति', 'लकी ड्रॉ', 'बक्षीस',
      // Regional (prize / lottery)
      'লটারি', 'পুরস্কার', 'பரிசு', 'லாட்டரி', 'బహుమతి', 'లాటరీ', 'ಬಹುಮಾನ', 'ಲಾಟರಿ',
      'സമ്മാനം', 'ലോട്ടറി', 'ઇનામ', 'લોટરી', 'ਇਨਾਮ', 'ਲਾਟਰੀ', 'ପୁରସ୍କାର', 'ଲଟେରୀ', 'انعام', 'لاٹری'
    ],
    impersonation: [
      'official notice', 'government', 'tax department', 'court order',
      'law enforcement', 'central bank', 'reserve bank', 'rbi', 'income tax', 'customs department',
      'cbi', 'police', 'cyber cell', 'trai', 'uidai', 'npci', 'sebi', 'electricity board',
      'सरकार', 'पुलिस', 'आयकर'
    ],
    grammar: ['kindly do the needful', 'dear sir/madam', 'dear sir or madam', 'dear customer', 'dear user', 'dear consumer', 'प्रिय ग्राहक'],
    money: [
      'wire transfer', 'western union', 'bitcoin', 'gift card', 'cryptocurrency',
      'pay immediately', 'transfer funds', 'send money', 'moneygram',
      'processing fee', 'advance fee', 'registration fee', 'security deposit', 'refundable deposit',
      // Hinglish / Hindi
      'paise bhejo', 'paisa bhejo', 'पैसे भेजें', 'शुल्क', 'फीस जमा'
    ],
    callToAction: [
      'click here', 'click the link', 'click below', 'verify your identity',
      'verify your account', 'confirm your identity', 'confirm your account',
      'update your information', 'update your details', 'reply with', 'open the attachment',
      'log in to', 'login to', 'sign in to', 'download the app', 'install the app', 'share the code',
      // Hinglish / Hindi / regional "click" and "call"
      'click karein', 'click kare', 'call karein', 'क्लिक करें', 'लिंक पर क्लिक', 'कॉल करें', 'क्लिक करा',
      'ক্লিক করুন', 'கிளிக் செய்யவும்', 'క్లిక్ చేయండి', 'ಕ್ಲಿಕ್ ಮಾಡಿ', 'ക്ലിക്ക് ചെയ്യുക', 'ક્લિક કરો', 'ਕਲਿੱਕ ਕਰੋ'
    ]
  };

  /**
   * The scams Indians most often receive. Each pattern describes the *shape* of the scam,
   * so ordinary messages that merely mention "electricity" or "KYC" don't trigger it.
   * A pattern is a RegExp, or an array of RegExps that must ALL match.
   * `critical` scams ask for something no legitimate organisation ever asks for, so they
   * score at least HIGH on their own.
   */
  const INDIA_SCAMS = [
    {
      id: 'otpShare',
      label: 'asks you to share an OTP',
      points: 30,
      critical: true,
      patterns: [
        /(share|send|tell|forward|give|batao|bataiye|bata\s*do|bhejo|बताएं|बताओ|बताइए|भेजें|शेयर)[\s\S]{0,30}(otp|ओटीपी|one[\s-]*time[\s-]*password|verification\s*code)/iu,
        /(otp|ओटीपी)[\s\S]{0,25}(share|batao|bataiye|bata\s*do|send|reply|बताएं|बताओ|भेजें)/iu,
        // Regional: an OTP word plus a "share" word
        [/(ওটিপি|ஓடிபி|ఓటీపీ|ಒಟಿಪಿ|ഒടിപി|ઓટીપી|ਓਟੀਪੀ|ଓଟିପି)/u, /(শেয়ার|பகிர|షేర్|ಶೇರ್|ಹಂಚಿ|ഷെയർ|શેર|ਸ਼ੇਅਰ|ସେୟାର)/u]
      ],
      // Genuine OTP messages say "do not share" — never flag those.
      unless: /(do\s*not|don'?t|never|not\s*to)\s+(share|disclose|tell|give)|(शेयर|साझा|बताएं)\s*(न|ना|मत)\b|(मत|न)\s*(करें\s*)?(शेयर|साझा)|শেয়ার\s*করবেন\s*না|பகிர\s*வேண்டாம்|షేర్\s*చేయవద్దు|ಹಂಚಿಕೊಳ್ಳಬೇಡಿ|ഷെയർ\s*ചെയ്യരുത്|શેર\s*ન|ਸ਼ੇਅਰ\s*ਨਾ/iu,
      advice: 'Never share an OTP with anyone, including people who say they are from your bank, a delivery company or the police. An OTP is your signature.'
    },
    {
      id: 'upiReceive',
      label: 'UPI "enter your PIN to receive money" trick',
      points: 30,
      critical: true,
      patterns: [
        /(upi\s*pin|enter\s*(your\s*)?pin|pin\s*(dal|daal|enter)|पिन\s*डाल)[\s\S]{0,100}(receive|refund|cashback|credit|prapt|प्राप्त|मिलेगा)/iu,
        /(receive|get|claim|refund|cashback|prapt|प्राप्त)[\s\S]{0,80}(upi\s*pin|enter\s*(your\s*)?pin|scan\s*(the\s*)?qr|collect\s*request)/iu
      ],
      advice: 'You never need to enter your UPI PIN or scan a QR code to RECEIVE money. Entering a PIN always sends money out of your account.'
    },
    {
      id: 'kyc',
      label: 'fake KYC / PAN update',
      points: 25,
      patterns: [
        [/(\bkyc\b|\bre-?kyc\b|\be-?kyc\b|केवाईसी)/iu, /(update|expir|pending|block|suspend|verify|complete|band|बंद|अपडेट)/iu],
        [/\bpan\s*(card|number)?\b/iu, /(block|suspend|deactivat|expir|\bband\b|बंद|link\s*(now|today|immediately)|click)/iu]
      ],
      advice: 'Banks never ask you to update KYC or link PAN through an SMS or WhatsApp link. Use your bank branch or official app.'
    },
    {
      id: 'electricity',
      label: 'electricity disconnection scam',
      points: 30,
      // All three clues must appear: a power reference, a disconnection threat, and a bill/officer/contact hook.
      patterns: [[
        /(electricity|bijli|बिजली|\bpower\b|\blight\b|current\s*bill|वीज|বিদ্যুৎ|மின்|కరెంట్|ವಿದ್ಯುತ್|വൈദ്യുതി|વીજ|ਬਿਜਲੀ)/iu,
        /(disconnect|\bcut\b|\bkat\b|काट|\bband\b|बंद|tonight|9[.:]?30)/iu,
        /(\bbill\b|officer|contact|\bcall\b|not\s*(been\s*)?updated|बिल|संपर्क|अपडेट)/iu
      ]],
      advice: "Electricity boards don't disconnect supply through an SMS from a personal number. Pay only on your board's official website or app."
    },
    {
      id: 'digitalArrest',
      label: 'fake police / CBI / customs ("digital arrest") threat',
      points: 30,
      critical: true,
      patterns: [
        /(digital\s*arrest|डिजिटल\s*अरेस्ट|money\s*laundering|narcotics|\bncb\b|enforcement\s*directorate|mumbai\s*police|cyber\s*(crime\s*)?(cell|branch)|parcel[\s\S]{0,80}(drugs|illegal|seized|passport)|your\s*(sim|number|mobile)[\s\S]{0,30}(blocked|disconnected|deactivated)[\s\S]{0,40}(trai|2\s*hours))/iu
      ],
      advice: 'Police, CBI, customs and TRAI never arrest, question or fine anyone over a video or phone call. There is no such thing as a "digital arrest". Hang up and call 1930.'
    },
    {
      id: 'taskJob',
      label: 'paid "task" job scam',
      points: 35,
      patterns: [
        /(daily\s*(income|earning|salary)|earn\s*(rs\.?|₹|inr)?\s*\d[\d,]*\s*(per|a|daily|\/)|like\s*(youtube\s*)?(videos|posts)|telegram\s*(task|group)|prepaid\s*task|rate\s*hotels|review\s*task|kamaye|kamao|कमाएं|कमाओ)/iu
      ],
      advice: 'Real jobs never ask you to pay a deposit or complete paid "tasks". Never send money to task apps or Telegram groups.'
    },
    {
      id: 'jobBait',
      label: 'unsolicited work-from-home offer',
      points: 10,
      patterns: [/(part[\s-]*time\s*job|work\s*from\s*home|ghar\s*baithe|घर\s*बैठे)/iu],
      advice: 'Be wary of unsolicited job offers by SMS or WhatsApp. Check the company on its official website before sharing documents.'
    },
    {
      id: 'investment',
      label: 'guaranteed-returns investment scam',
      points: 30,
      patterns: [
        /(stock\s*tips|guaranteed\s*(returns?|profit)|double\s*your\s*money|paisa\s*double|\d+\s*%\s*(daily|weekly|monthly)\s*(returns?|profit)|ipo\s*allotment|trading\s*group|vip\s*group|crypto\s*investment)/iu
      ],
      advice: 'SEBI-registered advisers never guarantee returns. Check any adviser on sebi.gov.in before investing.'
    },
    {
      id: 'loan',
      label: 'instant-loan app scam',
      points: 20,
      patterns: [
        /(instant\s*loan|pre-?approved\s*loan|loan\s*(approved|sanctioned)|without\s*cibil|no\s*cibil|low\s*cibil|loan\s*app)/iu
      ],
      advice: 'Borrow only from RBI-regulated lenders. Loan apps that ask for an upfront fee or access to your contacts are often illegal.'
    },
    {
      id: 'parcel',
      label: 'fake parcel / delivery problem',
      points: 20,
      patterns: [
        /(courier|parcel|package|shipment|india\s*post|speed\s*post)[\s\S]{0,120}(fee|pay|address\s*(update|incomplete|wrong)|held|on\s*hold|failed|re-?deliver|customs\s*duty)/iu
      ],
      advice: "India Post and courier companies don't ask you to pay small fees or update your address through SMS links."
    },
    {
      id: 'rewardPoints',
      label: 'fake bank reward-points offer',
      points: 25,
      patterns: [
        /(reward\s*points?|yono)[\s\S]{0,100}(expir|today|apk|link|claim|redeem)/iu
      ],
      advice: 'Banks never send reward-point links that ask you to install an app or enter card details. Check points only in the official app.'
    },
    {
      id: 'apk',
      label: 'asks you to install an APK app file',
      points: 30,
      critical: true,
      patterns: [/\.apk\b|\bapk\s*(file|download|install)|install\s*(this|the)\s*apk/iu],
      advice: 'Never install apps from links or WhatsApp files (.apk). Fake bank and "reward" apps steal OTPs and empty accounts. Use only the Play Store.'
    },
    {
      id: 'remoteAccess',
      label: 'asks you to install a screen-sharing app',
      points: 30,
      critical: true,
      patterns: [/(anydesk|any\s*desk|teamviewer|team\s*viewer|quick\s*support|rustdesk|airdroid|screen\s*shar)/iu],
      advice: 'Never install AnyDesk, TeamViewer or similar apps at a stranger\'s request. They let the scammer control your phone and bank apps.'
    }
  ];

  // Unicode script ranges → language names shown in results.
  const SCRIPTS = [
    // U+0964/0965 (danda) are shared by several scripts, so they don't count as Hindi.
    { name: 'Hindi/Marathi', re: /[ऀ-ॣ०-ॿ]/ },
    { name: 'Bengali/Assamese', re: /[ঀ-৿]/ },
    { name: 'Punjabi', re: /[਀-੿]/ },
    { name: 'Gujarati', re: /[઀-૿]/ },
    { name: 'Odia', re: /[଀-୿]/ },
    { name: 'Tamil', re: /[஀-௿]/ },
    { name: 'Telugu', re: /[ఀ-౿]/ },
    { name: 'Kannada', re: /[ಀ-೿]/ },
    { name: 'Malayalam', re: /[ഀ-ൿ]/ },
    { name: 'Urdu', re: /[؀-ۿ]/ }
  ];

  // Indian mobile number (10 digits starting 6–9, optional +91 / 0).
  const INDIAN_MOBILE = /(?:\+91[\s-]?|\b0)?\b[6-9]\d{4}[\s-]?\d{5}\b/;
  const CALL_PROMPT = /(call|contact|whatsapp|sampark|ring|dial|संपर्क|कॉल|फोन)/iu;

  const SAFE_LEVEL_FLOOR = [
    { max: 15, level: 'SAFE', cls: 'risk-safe' },
    { max: 35, level: 'LOW RISK', cls: 'risk-low' },
    { max: 55, level: 'MEDIUM RISK', cls: 'risk-medium' },
    { max: 75, level: 'HIGH RISK', cls: 'risk-high' },
    { max: 100, level: 'CRITICAL', cls: 'risk-critical' }
  ];

  const FINAL_RECOMMENDATION =
    'When in doubt, contact the organization directly using contact info from their official website.';

  // Ordered by importance — the first matches win when the list is trimmed.
  // India-specific advice comes first because it is the most actionable.
  const RECOMMENDATIONS = [
    ...INDIA_SCAMS.map((s) => ({ flags: ['india-' + s.id], text: s.advice })),
    { flags: ['upiPay'], text: 'Only approve a UPI request if you started the payment yourself and know the person. Decline unexpected collect requests.' },
    { flags: ['govLookalike'], text: 'Indian government websites always end in .gov.in or .nic.in. Pay challans, taxes and bills only on those sites.' },
    { flags: ['mobileContact'], text: 'Banks and government offices use official helplines (often 1800 numbers), not personal mobile numbers. Find the number on the official website.' },
    { flags: ['dataUri', 'doubleExt'], text: "Don't open or download anything from this link. Scan any file you already downloaded with antivirus software." },
    { flags: ['personal'], text: 'Never share OTPs, PINs, passwords, CVV, Aadhaar/SSN or bank details over message, email or phone. No real bank asks for them.' },
    { flags: ['money'], text: 'Never pay with gift cards, crypto, or wire transfers to someone you only know from a message. These payments cannot be reversed.' },
    { flags: ['lookalike', 'homoglyph', 'punycode', 'brandMisuse'], text: 'Check the domain letter by letter. Attackers swap look-alike characters or bolt brand names onto unrelated domains.' },
    { flags: ['link'], text: "Don't click links in this message. Open the official app or type the website address yourself." },
    { flags: ['ip', 'tld', 'subdomains', 'port', 'entropy'], text: "Type the official website address yourself instead of clicking. Legitimate services don't hide behind raw IPs or throwaway domains." },
    { flags: ['http'], text: "Never enter passwords or payment details on a page that doesn't use HTTPS." },
    { flags: ['atSymbol'], text: "Ignore everything before an '@' in a web address. The real destination is the part after it." },
    { flags: ['shortener'], text: 'Expand shortened links with a link-preview service before opening them, so you can see where they go.' },
    { flags: ['encoding'], text: 'Be wary of links stuffed with %-encoded characters. They are often used to hide the real target.' },
    { flags: ['urgency', 'fear'], text: 'Pause before acting. Real organizations rarely demand action within hours or threaten you with arrest or account closure.' },
    { flags: ['impersonation'], text: "Government agencies and banks don't send legal threats by SMS or email. Verify through their official helpline." },
    { flags: ['prize'], text: "If you didn't enter a contest, you didn't win one. Delete prize, lottery and inheritance messages." },
    { flags: ['grammar', 'callToAction'], text: 'Generic greetings, odd phrasing and "click here" prompts are classic signs of a mass phishing campaign.' },
    { flags: ['malformed'], text: "This doesn't parse as a valid web address. Double-check where it came from before using it." }
  ];

  class ThreatDetector {
    constructor() {
      this._termRegexCache = new Map();
    }

    /**
     * @param {string} input
     * @param {'url'|'message'} type
     * @returns {{score:number, level:string, levelClass:string, reasons:string[], recommendations:string[], positives:string[]}}
     */
    analyze(input, type) {
      const text = typeof input === 'string' ? input.trim() : '';
      if (!text) {
        return {
          score: 0,
          level: 'NO INPUT',
          levelClass: 'risk-safe',
          reasons: [],
          positives: [],
          recommendations: ['Paste a URL or message to analyze.', FINAL_RECOMMENDATION]
        };
      }

      try {
        const raw = type === 'message' ? this._analyzeMessage(text) : this._analyzeUrl(text);
        return this._finalize(raw);
      } catch (err) {
        console.error('[ThreatDetector] analysis failed:', err);
        return {
          score: 50,
          level: 'MEDIUM RISK',
          levelClass: 'risk-medium',
          reasons: ['The input could not be fully analyzed. Treat it with caution.'],
          positives: [],
          recommendations: [
            "Don't click links or share personal details until you've verified the source.",
            FINAL_RECOMMENDATION
          ]
        };
      }
    }

    // ------------------------------------------------------------------ URL

    _analyzeUrl(input) {
      const r = this._newResult();
      const add = (points, reason, flag) => this._add(r, points, reason, flag);

      // 12. Data / javascript URIs — nothing else to parse
      if (/^data:/i.test(input)) {
        add(30, 'Data URI can embed hidden executable content', 'dataUri');
        if (/text\/html|javascript|base64/i.test(input.slice(0, 80))) {
          add(15, 'Data URI contains HTML/script or base64 payload that runs when opened', 'dataUri');
        }
        return r;
      }
      if (/^javascript:/i.test(input)) {
        add(40, 'javascript: link runs code in your browser when opened', 'dataUri');
        return r;
      }

      // UPI payment links (upi://pay?pa=…&am=…) always move money OUT of the person who opens them.
      if (/^upi:/i.test(input)) {
        return this._analyzeUpiLink(input, r);
      }

      const parsed = this._parseUrl(input);
      if (!parsed) {
        add(10, "Couldn't be parsed as a valid URL. Malformed links are a common obfuscation trick", 'malformed');
        if (this._hasHomoglyphs(input)) {
          add(25, 'Contains look-alike Unicode characters (homoglyphs) used for domain spoofing', 'homoglyph');
        }
        return r;
      }

      const { url, hadScheme } = parsed;
      const host = url.hostname.toLowerCase().replace(/\.$/, '');
      const rawHost = this._rawHost(input);
      const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[') || host.includes(':');
      const registrable = isIp ? host : this._registrableDomain(host);
      const mainLabel = registrable.split('.')[0];
      const isGov = !isIp && GOV_SUFFIXES.some((s) => host === s || host.endsWith('.' + s));
      const isWhitelisted = isGov || (!isIp && SAFE_DOMAINS.some((d) => host === d || host.endsWith('.' + d)));

      // India: sites that pose as government but aren't on .gov.in / .nic.in (fake e-challan, PM-Kisan, ITR refund…)
      if (!isGov && !isIp && GOV_LOOKALIKE.test(host)) {
        add(30, `Looks like an Indian government site but isn't on .gov.in or .nic.in (real ones always are): ${registrable}`, 'govLookalike');
      }

      // Bait words in the domain itself ("kbc-lottery", "sbi-reward", "kyc-update")
      const bait = !isWhitelisted && !isIp && host.match(/(lottery|lucky|prize|reward|cashback|refund|kbc|kyc|bonus|gift|offer|winner|claim|free)/);
      if (bait) {
        add(15, `Domain name uses the bait word "${bait[1]}", typical of scam sites`, 'baitDomain');
      }

      // India: APK downloads are the main way fake bank / reward apps are spread
      if (/\.apk$/i.test(url.pathname)) {
        add(30, 'Downloads an Android app file (.apk) from outside the Play Store', 'india-apk');
      }

      // 1. Insecure protocol
      if (url.protocol === 'http:' && hadScheme) {
        add(15, 'Uses insecure HTTP. Data can be intercepted', 'http');
      } else if (url.protocol === 'https:') {
        r.positives.push('Uses an encrypted HTTPS connection (note: scammers can use HTTPS too)');
      }

      // 2. Raw IP address
      if (isIp) {
        add(25, 'Uses raw IP address instead of domain name, common in phishing', 'ip');
      }

      // 3. Suspicious TLD
      const tld = host.split('.').pop();
      if (!isIp && SUSPICIOUS_TLDS.includes(tld)) {
        add(15, `Uses suspicious TLD (.${tld}) frequently associated with malicious sites`, 'tld');
      }

      // 4. Excessive subdomains
      const dotCount = (host.match(/\./g) || []).length;
      if (!isIp && dotCount > 3) {
        add(10 * (dotCount - 3), 'Excessive subdomains used to disguise the real domain', 'subdomains');
      }

      // 5. Look-alike domain / brand misuse
      if (!isWhitelisted) {
        const lookalike = isIp ? null : this._findLookalikeBrand(mainLabel);
        const subLabels = isIp ? [] : host.split('.').slice(0, -registrable.split('.').length);
        const shortBrand = isIp ? null : SHORT_BRAND_PATTERNS.find((p) => p.re.test(host));
        const brandInDomain = isIp ? null : (BRANDS.find(
          (b) => (mainLabel !== b && mainLabel.includes(b)) || subLabels.some((l) => l.includes(b))
        ) || (shortBrand && shortBrand.brand.toUpperCase()));
        if (lookalike) {
          add(30, `Domain closely resembles '${lookalike}', likely impersonation`, 'lookalike');
        } else if (brandInDomain) {
          add(20, `Uses the brand name '${brandInDomain}' but isn't hosted on ${brandInDomain}'s official domain`, 'brandMisuse');
        } else if (isIp || !BRANDS.includes(mainLabel)) {
          const pathText = this._safeDecode(url.pathname + url.search).toLowerCase();
          const brandInPath = BRANDS.find((b) => pathText.includes(b));
          if (brandInPath) {
            add(15, `References '${brandInPath}' in the link but is hosted on ${registrable}`, 'brandMisuse');
          }
        }
      }

      // 6. URL shortener
      if (SHORTENERS.some((s) => host === s || host.endsWith('.' + s))) {
        add(10, 'URL shortener hides the real destination', 'shortener');
      }

      // 7. @ in authority (user-info trick: http://google.com@evil.tk)
      if (url.username || url.password || this._authority(input).includes('@')) {
        add(20, 'Contains @ symbol which can trick browsers about the real destination', 'atSymbol');
      }

      // 8. Percent / hex encoding
      const encoded = input.match(/%[0-9a-f]{2}/gi) || [];
      if (encoded.length > 2) {
        add(15, 'Contains encoded characters that may disguise malicious content', 'encoding');
      }

      // 9. Length
      if (input.length > 200) {
        add(10, 'Unusually long URL may hide suspicious parameters', 'length');
      } else if (input.length > 100) {
        add(5, 'Unusually long URL may hide suspicious parameters', 'length');
      }

      // 10. Suspicious path keywords
      const pathLower = this._safeDecode(url.pathname + url.search).toLowerCase();
      const pathHits = PATH_KEYWORDS.filter((k) => new RegExp(`(^|[^a-z])${k}([^a-z]|$)`).test(pathLower));
      if (pathHits.length) {
        add(Math.min(20, pathHits.length * 8), `URL path contains suspicious keywords: ${pathHits.join(', ')}`, 'pathKeywords');
      }

      // 11. Non-standard port
      if (url.port && url.port !== '80' && url.port !== '443') {
        add(15, `Uses non-standard port (${url.port}), unusual for legitimate sites`, 'port');
      }

      // 13. Homoglyphs (checked on the raw input — URL() converts them to punycode)
      if (this._hasHomoglyphs(rawHost)) {
        add(25, 'Contains look-alike Unicode characters (homoglyphs) used for domain spoofing', 'homoglyph');
      }

      // 14. Entropy
      if (!isIp && this._calculateEntropy(host.replace(/\./g, '')) > 4.0) {
        add(10, 'Domain has unusually random characters and may be auto-generated', 'entropy');
      }

      // 15. Double extension
      if (/\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|php|html?|zip|mp3|mp4|exe)\.(exe|scr|bat|cmd|js|vbs|html?|php|pdf|jar|apk|msi)$/i.test(url.pathname)) {
        add(15, 'Double file extension, a common malware delivery trick', 'doubleExt');
      }

      // 16. Punycode / IDN
      if (host.split('.').some((label) => label.startsWith('xn--'))) {
        add(15, 'Uses internationalized domain (Punycode) which can mask the real domain', 'punycode');
      }

      // 17. Known-safe domain bonus
      if (isWhitelisted) {
        r.score -= 30;
        r.positives.push(isGov
          ? `${registrable} is an official Indian government domain (.gov.in / .nic.in)`
          : `${registrable} is a well-known, trusted domain`);
      }

      r.meta = { host, registrable };
      return r;
    }

    // -------------------------------------------------------------- MESSAGE

    _analyzeMessage(input) {
      const r = this._newResult();
      const text = this._toAsciiDigits(input).replace(/[‘’ʼ]/g, "'").replace(/[“”]/g, '"');
      r.languages = this._detectLanguages(text);
      const add = (points, reason, flag) => this._add(r, points, reason, flag);
      const find = (terms) => terms.filter((t) => this._containsTerm(text, t));
      const quote = (list) => list.map((t) => `"${t}"`).join(', ');
      const tactics = new Set();

      // 1. Urgency
      const urgency = find(MESSAGE_RULES.urgency);
      const deadline = text.match(/\bwithin\s+\d+\s*(hours?|hrs?|minutes?|mins?|days?)\b/i);
      if (deadline) urgency.push(deadline[0].toLowerCase());
      if (urgency.length) {
        add(Math.min(20, urgency.length * 4), `Contains ${urgency.length} urgency trigger(s): ${quote(urgency)}`, 'urgency');
        tactics.add('urgency');
      }

      // 2. Fear / threat
      const fear = find(MESSAGE_RULES.fear);
      if (fear.length) {
        add(Math.min(25, fear.length * 5), `Uses fear or threat language: ${quote(fear)}`, 'fear');
        tactics.add('fear');
      }

      // 3. Personal info requests
      const personal = find(MESSAGE_RULES.personal);
      if (personal.length) {
        add(Math.min(30, personal.length * 8), `Asks for sensitive personal information: ${quote(personal)}`, 'personal');
        tactics.add('personal');
      }

      // India-specific scam shapes (OTP sharing, UPI PIN trick, KYC, electricity, digital arrest, task jobs…)
      let indiaMatches = 0;
      for (const scam of INDIA_SCAMS) {
        const matched = scam.patterns.some((p) => (Array.isArray(p) ? p.every((re) => re.test(text)) : p.test(text)))
          && !(scam.unless && scam.unless.test(text));
        if (matched) {
          add(scam.points, `Matches a common Indian scam: ${scam.label}`, 'india-' + scam.id);
          tactics.add('india');
          indiaMatches++;
          // Asking for these is never legitimate, so the message is at least HIGH risk on its own.
          if (scam.critical) r.minScore = Math.max(r.minScore || 0, 60);
        }
      }
      if (indiaMatches >= 2) {
        add(10, `Combines ${indiaMatches} known Indian scam patterns`, 'combined');
      }

      // Asking you to call / WhatsApp a personal mobile number instead of an official helpline
      if (INDIAN_MOBILE.test(text) && CALL_PROMPT.test(text)) {
        add(12, 'Asks you to call or WhatsApp a personal mobile number instead of an official helpline', 'mobileContact');
        tactics.add('contact');
      }

      // 4. Embedded URLs
      const urls = this._extractUrls(text);
      if (urls.length) {
        let worst = null;
        for (const u of urls) {
          const res = this._analyzeUrl(u);
          res.score = Math.max(0, res.score);
          if (!worst || res.score > worst.result.score) worst = { url: u, result: res };
        }
        if (worst && worst.result.score > 30) {
          const linkPoints = Math.round(worst.result.score * 0.6);
          const why = worst.result.reasons.slice(0, 2).join('; ');
          add(linkPoints, `Contains a high-risk link: ${worst.url} (link risk ${worst.result.score}/100: ${why})`, 'link');
          worst.result.flags.forEach((f) => r.flags.add(f));
          tactics.add('link');
        } else if (worst) {
          r.positives.push(`Linked domain${urls.length > 1 ? 's look' : ' looks'} low-risk (${urls.join(', ')})`);
        }
      }

      // 5. Too good to be true
      const prize = find(MESSAGE_RULES.prize);
      if (prize.length) {
        add(Math.min(20, prize.length * 4), `Offer sounds too good to be true: ${quote(prize)}`, 'prize');
        tactics.add('prize');
      }

      // 6. Authority impersonation
      const authority = find(MESSAGE_RULES.impersonation);
      if (authority.length) {
        add(Math.min(15, authority.length * 5), `Claims to come from an authority: ${quote(authority)}`, 'impersonation');
        tactics.add('impersonation');
      }

      // 7. Poor grammar / mass-mail patterns
      const grammar = find(MESSAGE_RULES.grammar);
      const exclamations = (text.match(/!/g) || []).length;
      if (exclamations > 3) grammar.push(`${exclamations} exclamation marks`);
      const capsWords = (text.match(/\b[A-Z]{2,}\b/g) || []).filter((w) => !/^(OTP|PIN|SSN|CVV|ATM|UPI|PAN|KYC|USA|UK|ID|OK|AM|PM|IRS|URL|SMS)$/.test(w));
      if (capsWords.length > 3) grammar.push(`${capsWords.length} ALL-CAPS words`);
      if (grammar.length) {
        add(Math.min(15, grammar.length * 3), `Shows mass-phishing writing patterns: ${quote(grammar)}`, 'grammar');
      }

      // 8. Money / payment pressure
      const money = find(MESSAGE_RULES.money);
      if (money.length) {
        add(Math.min(25, money.length * 7), `Pressures you to pay through hard-to-trace methods: ${quote(money)}`, 'money');
        tactics.add('money');
      }

      // 9. Short message + link
      if (text.length < 50 && urls.length) {
        add(10, 'Very short message with a link, typical of SMS phishing ("smishing")', 'shortLink');
      }

      // 10. Call-to-action pressure
      const cta = find(MESSAGE_RULES.callToAction);
      if (cta.length) {
        add(Math.min(15, cta.length * 5), `Pushes you to take a specific action: ${quote(cta)}`, 'callToAction');
        tactics.add('cta');
      }

      // 11. Several independent tactics combined is a strong signal on its own
      if (tactics.size >= 3) {
        add(10, `Combines ${tactics.size} different manipulation tactics in one message`, 'combined');
      }

      if (!r.reasons.length) {
        r.positives.push('No urgency, threats, payment pressure or requests for personal data detected');
      }
      return r;
    }

    // ------------------------------------------------------------- RESULTS

    _newResult() {
      return { score: 0, reasons: [], flags: new Set(), positives: [] };
    }

    _add(result, points, reason, flag) {
      result.score += points;
      result.reasons.push(reason);
      if (flag) result.flags.add(flag);
    }

    _finalize(raw) {
      const score = Math.max(raw.minScore || 0, Math.min(100, Math.round(raw.score)), 0);
      const band = SAFE_LEVEL_FLOOR.find((b) => score <= b.max) || SAFE_LEVEL_FLOOR[SAFE_LEVEL_FLOOR.length - 1];
      return {
        score,
        level: band.level,
        levelClass: band.cls,
        // Named Indian scam matches are the most telling finding, so they go first.
        reasons: raw.reasons.slice().sort((a, b) => Number(b.startsWith('Matches a common Indian scam')) - Number(a.startsWith('Matches a common Indian scam'))),
        positives: raw.positives.slice(),
        languages: raw.languages || [],
        recommendations: this._buildRecommendations(raw.flags, score)
      };
    }

    /** upi://pay?pa=<vpa>&pn=<name>&am=<amount> */
    _analyzeUpiLink(input, r) {
      const add = (points, reason, flag) => this._add(r, points, reason, flag);
      let params;
      try {
        params = new URLSearchParams(input.slice(input.indexOf('?') + 1));
      } catch (err) {
        params = new URLSearchParams();
      }
      const vpa = (params.get('pa') || '').toLowerCase();
      const payee = params.get('pn') || '';
      const amount = params.get('am') || '';

      add(25, `This is a UPI payment request: opening it sends money FROM your account${amount ? ` (₹${amount})` : ''}${vpa ? ` to ${vpa}` : ''}`, 'upiPay');
      if (/(refund|support|care|help|kyc|reward|cashback|prize|lottery|gift|bonus|claim|customer|official|verify)/.test(vpa + ' ' + payee.toLowerCase())) {
        add(30, `The payee ("${payee || vpa}") pretends to be a refund, cashback or support account. Real refunds never need you to pay`, 'india-upiReceive');
      }
      const brand = BRANDS.concat(['sbi', 'pnb', 'jio']).find((b) => vpa.split('@')[0].includes(b));
      if (brand) {
        add(15, `The UPI ID uses the brand name '${brand}', a common impersonation trick`, 'brandMisuse');
      }
      return r;
    }

    /** Names of the Indian scripts used in a text, plus English if Latin text is present. */
    _detectLanguages(text) {
      const found = SCRIPTS.filter((s) => s.re.test(text)).map((s) => s.name);
      if (/[A-Za-z]{3,}/.test(text)) found.push('English');
      return found;
    }

    /** Converts Devanagari, Bengali, Gurmukhi, Gujarati, Odia, Tamil, Telugu, Kannada and Malayalam digits to 0–9. */
    _toAsciiDigits(text) {
      return String(text).replace(/[०-९০-৯੦-੯૦-૯୦-୯௦-௯౦-౯೦-೯൦-൯]/g,
        (ch) => String(ch.charCodeAt(0) % 16 - 6));
    }

    _buildRecommendations(flags, score) {
      const recs = [];
      for (const rule of RECOMMENDATIONS) {
        if (rule.flags.some((f) => flags.has(f))) recs.push(rule.text);
      }

      if (score >= 56) {
        recs.unshift('Do not reply, click or pay. Report it at cybercrime.gov.in or call 1930 (if money was lost, call within the first hour so the transfer can be frozen). Report fraud SMS and calls on Sanchar Saathi (Chakshu).');
      }

      const padding = score <= 15
        ? [
            'No strong threat signals found, but stay alert. New scams may not trigger every check.',
            'Only proceed if you were expecting this link or message from someone you know.',
            'Keep your browser and device updated so known malicious sites are blocked.'
          ]
        : [
            'Verify the sender through a separate, trusted channel before responding.',
            'Turn on two-factor authentication for your important accounts.',
            'Keep your browser and device updated so known malicious sites are blocked.'
          ];

      for (const p of padding) {
        if (recs.length >= 2) break;
        recs.push(p);
      }

      const unique = Array.from(new Set(recs)).slice(0, 5);
      unique.push(FINAL_RECOMMENDATION);
      return unique;
    }

    // ------------------------------------------------------------- HELPERS

    /** Shannon entropy in bits per character. */
    _calculateEntropy(str) {
      if (!str) return 0;
      const counts = {};
      for (const ch of str) counts[ch] = (counts[ch] || 0) + 1;
      const len = str.length;
      let entropy = 0;
      for (const ch in counts) {
        const p = counts[ch] / len;
        entropy -= p * Math.log2(p);
      }
      return entropy;
    }

    /** Extracts http(s) URLs, www.* hosts, and bare domain names from free text. */
    _extractUrls(text) {
      if (!text) return [];
      const pattern = /\b((?:https?:\/\/|www\.|upi:\/\/)[^\s<>"'()]+|(?:[a-z0-9-]+\.)+[a-z]{2,24}(?::\d{2,5})?(?:\/[^\s<>"'()]*)?)/gi;
      const found = [];
      let m;
      while ((m = pattern.exec(text)) !== null) {
        let candidate = m[1].replace(/[.,;:!?)\]}'"]+$/, '');
        // Ignore e-mail addresses and plain numbers like "1.5"
        const before = text[m.index - 1];
        if (before === '@') continue;
        if (/^[\d.]+$/.test(candidate) && !/^\d{1,3}(\.\d{1,3}){3}$/.test(candidate)) continue;
        if (!/^https?:\/\//i.test(candidate) && !/^www\./i.test(candidate)) {
          const tld = candidate.split('/')[0].split(':')[0].split('.').pop().toLowerCase();
          if (!/^[a-z]{2,24}$/.test(tld)) continue;
        }
        if (!found.includes(candidate)) found.push(candidate);
      }
      return found;
    }

    /** Classic Levenshtein edit distance (two-row DP). */
    _levenshtein(a, b) {
      if (a === b) return 0;
      if (!a.length) return b.length;
      if (!b.length) return a.length;
      let prev = new Array(b.length + 1);
      let curr = new Array(b.length + 1);
      for (let j = 0; j <= b.length; j++) prev[j] = j;
      for (let i = 1; i <= a.length; i++) {
        curr[0] = i;
        for (let j = 1; j <= b.length; j++) {
          const cost = a[i - 1] === b[j - 1] ? 0 : 1;
          curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
        }
        [prev, curr] = [curr, prev];
      }
      return prev[b.length];
    }

    _hasHomoglyphs(str) {
      if (!str) return false;
      for (const ch of str) {
        if (HOMOGLYPHS[ch]) return true;
      }
      return false;
    }

    /** Returns { url, hadScheme } or null. Bare domains are parsed as http:// without being flagged. */
    _parseUrl(urlStr) {
      const s = String(urlStr || '').trim();
      if (!s || /\s/.test(s)) return null;
      const hadScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s);
      try {
        const url = new URL(hadScheme ? s : 'http://' + s);
        if (!url.hostname) return null;
        if (!['http:', 'https:', 'ftp:'].includes(url.protocol)) return null;
        return { url, hadScheme };
      } catch (err) {
        return null;
      }
    }

    // --- private utilities ---

    _findLookalikeBrand(label) {
      if (!label || label.length < 4 || BRANDS.includes(label)) return null;
      const normalized = label.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/rn/g, 'm');
      for (const brand of BRANDS) {
        // Short brands tolerate one edit; longer ones two — avoids flagging ordinary words.
        const maxEdits = brand.length >= 6 ? 2 : 1;
        if (normalized === brand) return brand;
        const d = this._levenshtein(label, brand);
        if (d > 0 && d <= maxEdits) return brand;
      }
      return null;
    }

    _registrableDomain(host) {
      const parts = host.split('.').filter(Boolean);
      if (parts.length <= 2) return parts.join('.');
      const lastTwo = parts.slice(-2).join('.');
      return MULTI_LABEL_SUFFIXES.includes(lastTwo) ? parts.slice(-3).join('.') : lastTwo;
    }

    /** "scheme://user@host:port" → "user@host:port" (without path/query/fragment). */
    _authority(input) {
      const withoutScheme = input.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
      return withoutScheme.split(/[/?#]/)[0];
    }

    /** Host exactly as typed (before URL() punycode-encodes it). */
    _rawHost(input) {
      const authority = this._authority(input);
      const afterAt = authority.slice(authority.lastIndexOf('@') + 1);
      return afterAt.replace(/:\d+$/, '').toLowerCase();
    }

    _safeDecode(str) {
      try {
        return decodeURIComponent(str);
      } catch (err) {
        return str;
      }
    }

    _containsTerm(text, term) {
      let re = this._termRegexCache.get(term);
      if (!re) {
        const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
        re = new RegExp(`(?<![\\w'])${escaped}(?![\\w'])`, 'i');
        this._termRegexCache.set(term, re);
      }
      return re.test(text);
    }
  }

  window.ThreatDetector = ThreatDetector;
})();
