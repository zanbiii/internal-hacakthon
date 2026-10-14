/**
 * CyberSeal — Threat Detector
 * Heuristic, fully client-side phishing / fraud analysis for URLs and messages.
 * Exposes window.ThreatDetector.
 */
(function () {
  'use strict';

  const SUSPICIOUS_TLDS = [
    'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'club', 'work',
    'click', 'link', 'buzz', 'icu', 'rest'
  ];

  const BRANDS = [
    'google', 'paypal', 'amazon', 'facebook', 'microsoft', 'apple', 'netflix',
    'instagram', 'twitter', 'linkedin', 'whatsapp', 'chase', 'wellsfargo',
    'citibank', 'dropbox', 'yahoo', 'outlook'
  ];

  const SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.cc', 't.ly'
  ];

  const SAFE_DOMAINS = [
    'google.com', 'youtube.com', 'github.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'facebook.com', 'twitter.com', 'x.com', 'linkedin.com',
    'wikipedia.org', 'stackoverflow.com', 'reddit.com', 'netflix.com',
    'instagram.com', 'whatsapp.com', 'vercel.app'
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

  const MESSAGE_RULES = {
    urgency: [
      'urgent', 'immediately', 'now', 'asap', 'hurry', 'limited time', 'act now',
      'expire', 'expires', 'expiring', 'deadline', 'right away', "don't delay",
      'last chance', 'final warning'
    ],
    fear: [
      'account suspended', 'suspended', 'compromised', 'unauthorized', 'illegal activity',
      'legal action', 'arrested', 'arrest', 'locked', 'terminated', 'violation',
      'hacked', 'blocked', 'seized', 'frozen'
    ],
    personal: [
      'ssn', 'social security', 'password', 'credit card', 'bank account',
      'date of birth', 'pin', 'cvv', 'routing number', 'otp', 'verification code',
      "mother's maiden", 'aadhaar', 'pan card', 'upi pin'
    ],
    prize: [
      'won', 'winner', 'congratulations', 'prize', 'lottery', 'million',
      'inheritance', 'beneficiary', 'claim your', 'selected for', 'lucky', 'jackpot'
    ],
    impersonation: [
      'official notice', 'government', 'irs', 'tax department', 'court order',
      'law enforcement', 'central bank', 'reserve bank', 'income tax', 'customs department'
    ],
    grammar: ['kindly do the needful', 'dear sir/madam', 'dear sir or madam', 'dear customer', 'dear user'],
    money: [
      'wire transfer', 'western union', 'bitcoin', 'gift card', 'cryptocurrency',
      'pay immediately', 'transfer funds', 'send money', 'moneygram', 'cash app',
      'zelle', 'processing fee', 'advance fee'
    ],
    callToAction: [
      'click here', 'click the link', 'click below', 'verify your identity',
      'verify your account', 'confirm your identity', 'confirm your account',
      'update your information', 'update your details', 'reply with', 'open the attachment',
      'log in to', 'login to', 'sign in to'
    ]
  };

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
  const RECOMMENDATIONS = [
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
      const isWhitelisted = !isIp && SAFE_DOMAINS.some((d) => host === d || host.endsWith('.' + d));

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
        const brandInDomain = isIp ? null : BRANDS.find(
          (b) => (mainLabel !== b && mainLabel.includes(b)) || subLabels.some((l) => l.includes(b))
        );
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
        r.positives.push(`${registrable} is a well-known, trusted domain`);
      }

      r.meta = { host, registrable };
      return r;
    }

    // -------------------------------------------------------------- MESSAGE

    _analyzeMessage(input) {
      const r = this._newResult();
      const text = input.replace(/[‘’ʼ]/g, "'").replace(/[“”]/g, '"');
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
      const score = Math.max(0, Math.min(100, Math.round(raw.score)));
      const band = SAFE_LEVEL_FLOOR.find((b) => score <= b.max) || SAFE_LEVEL_FLOOR[SAFE_LEVEL_FLOOR.length - 1];
      return {
        score,
        level: band.level,
        levelClass: band.cls,
        reasons: raw.reasons.slice(),
        positives: raw.positives.slice(),
        recommendations: this._buildRecommendations(raw.flags, score)
      };
    }

    _buildRecommendations(flags, score) {
      const recs = [];
      for (const rule of RECOMMENDATIONS) {
        if (rule.flags.some((f) => flags.has(f))) recs.push(rule.text);
      }

      if (score >= 56) {
        recs.unshift('Do not interact with this. Delete it, and report it (in India: call 1930 or file at cybercrime.gov.in).');
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
      const pattern = /\b((?:https?:\/\/|www\.)[^\s<>"'()]+|(?:[a-z0-9-]+\.)+[a-z]{2,24}(?::\d{2,5})?(?:\/[^\s<>"'()]*)?)/gi;
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
