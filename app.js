// ── Brand definitions ─────────────────────────────────────────
// Each brand has its official domains and keyword patterns to detect
// impersonation attempts in URLs.

const BRANDS = [
  { name: 'Instagram',      legit: ['instagram.com'],                              keywords: ['instagram', 'insta', 'ig'] },
  { name: 'Facebook',       legit: ['facebook.com', 'fb.com'],                     keywords: ['facebook', 'fb', 'faceb', 'face-book'] },
  { name: 'WhatsApp',       legit: ['whatsapp.com'],                               keywords: ['whatsapp', 'whats-app', 'watsapp', 'whatssapp'] },
  { name: 'Twitter / X',    legit: ['twitter.com', 'x.com'],                       keywords: ['twitter', 'twiter', 'twitt', 'twittr'] },
  { name: 'PayPal',         legit: ['paypal.com'],                                 keywords: ['paypal', 'paypa', 'paypai', 'paypa1'] },
  { name: 'Amazon',         legit: ['amazon.com', 'amazon.co.uk', 'amazon.in'],   keywords: ['amazon', 'amaz0n', 'arnazon', 'amazom'] },
  { name: 'Netflix',        legit: ['netflix.com'],                                keywords: ['netflix', 'netfl1x', 'netfix', 'neftlix', 'netf1ix'] },
  { name: 'Google',         legit: ['google.com', 'gmail.com', 'accounts.google.com'], keywords: ['google', 'g00gle', 'gogle', 'googie'] },
  { name: 'Apple',          legit: ['apple.com', 'icloud.com'],                   keywords: ['apple', 'icloud', 'itunes', 'appleid'] },
  { name: 'Microsoft',      legit: ['microsoft.com', 'live.com', 'outlook.com', 'office.com'], keywords: ['microsoft', 'micros0ft', 'mircosoft', 'outlook'] },
  { name: 'Bank of America',legit: ['bankofamerica.com'],                          keywords: ['bankofamerica', 'bankamerica', 'bofa'] },
  { name: 'YouTube',        legit: ['youtube.com'],                                keywords: ['youtube', 'y0utube', 'youtub', 'you-tube'] },
  { name: 'LinkedIn',       legit: ['linkedin.com'],                               keywords: ['linkedin', 'linked1n', 'linkedln', 'linke-din'] },
  { name: 'Snapchat',       legit: ['snapchat.com'],                               keywords: ['snapchat', 'snap-chat', 'snapcht'] },
  { name: 'TikTok',         legit: ['tiktok.com'],                                 keywords: ['tiktok', 'tik-tok', 'tikt0k'] },
  { name: 'Telegram',       legit: ['telegram.org', 't.me'],                       keywords: ['telegram', 'telegra', 'tele-gram'] },
  { name: 'Discord',        legit: ['discord.com', 'discord.gg'],                 keywords: ['discord', 'disc0rd', 'discrod'] },
];

// Suspicious TLDs commonly used for free/phishing domains
const SUSPICIOUS_TLDS = [
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click',
  'loan', 'work', 'party', 'review', 'trade', 'date', 'win',
  'download', 'men', 'bid', 'webcam', 'stream', 'racing', 'faith', 'science'
];

// Known URL shorteners that hide destinations
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl',
  'ow.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at'
];

// Paths commonly used on credential-harvesting pages
const SUSPICIOUS_PATHS = [
  '/login', '/signin', '/verify', '/account',
  '/secure', '/update', '/confirm', '/billing',
  '/reset', '/auth', '/password', '/credentials'
];

// Meter and icon colors per risk level
const METER_COLORS = { high: '#E24B4A', medium: '#EF9F27', low: '#c8c800', safe: '#1D9E75' };
const ICON_COLORS  = { high: '#a32d2d', medium: '#854f0b', low: '#6b6b00', safe: '#3b6d11' };


// ── URL parsing ───────────────────────────────────────────────

/**
 * Safely parses a raw URL string into a URL object.
 * Prepends http:// if no protocol is present.
 */
function parseURL(raw) {
  try {
    if (!/^https?:\/\//i.test(raw)) raw = 'http://' + raw;
    return new URL(raw);
  } catch (e) {
    return null;
  }
}


// ── Core analysis ─────────────────────────────────────────────

/**
 * Analyses a parsed URL for phishing indicators.
 * Returns { score, level, cls, verdict, tip, findings, detectedBrand }.
 */
function analyzeURL(parsed) {
  const hostname    = parsed.hostname.toLowerCase().replace(/^www\./, '');
  const pathQuery   = (parsed.pathname + parsed.search).toLowerCase();
  const findings    = [];
  let   score       = 0;
  let   detectedBrand = null;

  // ── 1. Brand impersonation ──
  for (const brand of BRANDS) {
    const isLegit    = brand.legit.some(d => hostname === d || hostname.endsWith('.' + d));
    const hasKeyword = brand.keywords.some(k => hostname.includes(k));

    if (hasKeyword || isLegit) {
      detectedBrand = brand.name;

      if (hasKeyword && !isLegit) {
        findings.push({
          icon:   'ti-alert-triangle',
          cat:    `Impersonating ${brand.name}`,
          detail: `"${hostname}" is not the official ${brand.name} domain`,
          score:  50
        });
        score += 50;
      }
      break;
    }
  }

  // ── 2. Suspicious TLD ──
  const tld = hostname.split('.').pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    findings.push({
      icon:   'ti-world-x',
      cat:    'Suspicious domain extension',
      detail: `.${tld} is commonly used for free or phishing domains`,
      score:  25
    });
    score += 25;
  }

  // ── 3. IP address URL ──
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    findings.push({
      icon:   'ti-server',
      cat:    'IP address instead of domain',
      detail: `URL uses a raw IP address: ${hostname}`,
      score:  30
    });
    score += 30;
  }

  // ── 4. URL shortener ──
  if (URL_SHORTENERS.some(s => hostname.includes(s))) {
    findings.push({
      icon:   'ti-link',
      cat:    'URL shortener detected',
      detail: 'Shortened URLs can hide the true malicious destination',
      score:  20
    });
    score += 20;
  }

  // ── 5. Excessive subdomains ──
  const domainParts = hostname.split('.');
  if (domainParts.length > 3) {
    findings.push({
      icon:   'ti-layers-subtract',
      cat:    'Excessive subdomains',
      detail: `"${hostname}" has an unusual number of subdomains`,
      score:  15
    });
    score += 15;
  }

  // ── 6. Hyphens in domain ──
  const domainWithoutTLD = domainParts.slice(0, -1).join('.');
  if (/-/.test(domainWithoutTLD)) {
    findings.push({
      icon:   'ti-minus',
      cat:    'Hyphenated domain name',
      detail: 'Hyphens in domain names are a common phishing tactic',
      score:  10
    });
    score += 10;
  }

  // ── 7. Character substitution (e.g. 0→o, 1→l) ──
  if (/[0@][a-z]|[a-z][0@]|1[a-z]|[a-z]1/.test(domainWithoutTLD)) {
    findings.push({
      icon:   'ti-letter-case',
      cat:    'Look-alike character substitution',
      detail: 'Uses characters like 0, 1, or @ to visually mimic real brand names',
      score:  20
    });
    score += 20;
  }

  // ── 8. Credential harvest path ──
  const matchedPath = SUSPICIOUS_PATHS.find(p => pathQuery.includes(p));
  if (matchedPath && score > 0) {
    findings.push({
      icon:   'ti-key',
      cat:    'Credential harvest path',
      detail: `Path contains "${matchedPath}" — typical of phishing login pages`,
      score:  15
    });
    score += 15;
  }

  // ── 9. No HTTPS ──
  if (parsed.protocol === 'http:' && score > 10) {
    findings.push({
      icon:   'ti-lock-open',
      cat:    'No HTTPS encryption',
      detail: 'Uses insecure HTTP — legitimate sites always use HTTPS',
      score:  10
    });
    score += 10;
  }

  // ── Determine risk level ──
  let level, cls, verdict, tip;

  if (score >= 60) {
    level   = 'HIGH RISK';
    cls     = 'high';
    verdict = 'This link shows strong signs of phishing. Do not visit it, enter any credentials, or share personal information.';
    tip     = 'If you received this link in a message or email, report it as spam and block the sender.';
  } else if (score >= 30) {
    level   = 'SUSPICIOUS';
    cls     = 'medium';
    verdict = 'This link has suspicious characteristics. Verify it through official channels before proceeding.';
    tip     = 'Always navigate directly to official websites (e.g. instagram.com) rather than clicking links in messages.';
  } else if (score >= 10) {
    level   = 'LOW RISK';
    cls     = 'low';
    verdict = 'Some minor concerns detected. Proceed with caution and double-check the domain carefully.';
    tip     = 'Look at the domain name carefully — phishing sites often use slight misspellings of real brands.';
  } else {
    level   = 'LOOKS SAFE';
    cls     = 'safe';
    verdict = 'No phishing indicators detected. This appears to be a legitimate URL.';
    tip     = 'No automated tool can guarantee a URL is 100% safe. Always stay cautious online.';
  }

  return { score, level, cls, verdict, tip, findings, detectedBrand };
}


// ── DOM rendering ─────────────────────────────────────────────

/** Builds and injects the result card into #result. */
function renderResult(parsed, analysis) {
  const { score, level, cls, verdict, tip, findings, detectedBrand } = analysis;
  const pct      = Math.min(100, Math.round(score / 1.2));
  const meterCol = METER_COLORS[cls];
  const iconCol  = ICON_COLORS[cls];

  const findingsHtml = findings.length
    ? findings.map(f => `
        <div class="finding">
          <i class="ti ${f.icon} finding-icon" aria-hidden="true" style="color:${iconCol}"></i>
          <div>
            <div class="finding-cat">${f.cat}</div>
            <div class="finding-detail">${f.detail}</div>
          </div>
        </div>`
      ).join('')
    : `<p style="font-size:14px;color:var(--text-muted);padding:6px 0">No suspicious indicators found.</p>`;

  const brandHtml = detectedBrand
    ? `<div class="brand-row">
         <span class="brand-label">Brand detected:</span>
         <span class="brand-chip">${detectedBrand}</span>
       </div>`
    : '';

  document.getElementById('result').innerHTML = `
    <div class="card ${cls}">

      <div class="card-header">
        <div>
          <div class="card-header-title">Scan result</div>
          <div class="score-text">Risk score: <strong>${score}</strong></div>
        </div>
        <span class="badge">${level}</span>
      </div>

      <div class="meter">
        <div class="meter-fill" style="width:${pct}%; background:${meterCol}"></div>
      </div>

      <div class="url-display">
        <i class="ti ti-link" aria-hidden="true" style="margin-right:4px"></i>${parsed.href}
      </div>

      ${brandHtml}

      <div class="verdict-text">${verdict}</div>

      <div class="findings-section">
        <div class="findings-title">FINDINGS (${findings.length})</div>
        ${findingsHtml}
      </div>

      <div class="tip">
        <i class="ti ti-bulb" aria-hidden="true" style="margin-right:4px"></i>${tip}
      </div>

    </div>`;
}


// ── UI actions ────────────────────────────────────────────────

/** Reads the input, runs analysis, and renders the result. */
function scan() {
  const raw = document.getElementById('url-input').value.trim();

  if (!raw) {
    document.getElementById('result').innerHTML = '';
    return;
  }

  const parsed = parseURL(raw);

  if (!parsed) {
    document.getElementById('result').innerHTML = `
      <div class="card low">
        <div class="card-header">
          <div class="card-header-title">Invalid URL</div>
          <span class="badge">Invalid</span>
        </div>
        <div class="verdict-text">
          Could not parse this URL. Make sure it starts with http:// or https://
        </div>
      </div>`;
    return;
  }

  const analysis = analyzeURL(parsed);
  renderResult(parsed, analysis);
}

/** Loads an example URL into the input and scans it. */
function load(url) {
  document.getElementById('url-input').value = url;
  scan();
}

/** Clears the input and result area. */
function clearAll() {
  document.getElementById('url-input').value = '';
  document.getElementById('result').innerHTML = '';
}

// Allow pressing Enter in the input to trigger a scan
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('url-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') scan();
  });
});
