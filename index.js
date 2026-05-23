const express = require('express');
const fs      = require('fs');
const dns     = require('dns').promises;
const cors    = require('cors');
const path    = require('path');
const { v4: uuidv4 } = require('uuid');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : [
      'http://localhost:3000',
      'http://127.0.0.1:5500',
      'null'
    ];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(null, false);
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-api-key'],
  credentials: false,
  optionsSuccessStatus: 200
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.set('trust proxy', 1);

// ─── File Paths ───────────────────────────────────────────────────────────────
const DOMAINS_FILE    = path.join(__dirname, 'disposable_domains.json');
const API_KEYS_FILE   = path.join(__dirname, 'api_keys.json');
const ANALYTICS_FILE  = path.join(__dirname, 'analytics.json');
const WEBHOOKS_FILE   = path.join(__dirname, 'webhooks.json');

// ─── Load Disposable Domains ──────────────────────────────────────────────────
let disposableDomains = new Set();
if (fs.existsSync(DOMAINS_FILE)) {
  try {
    const raw = JSON.parse(fs.readFileSync(DOMAINS_FILE, 'utf8'));
    disposableDomains = new Set(raw);
    console.log(`✓ Loaded ${disposableDomains.size} disposable domains`);
  } catch (err) {
    console.error('✗ Failed to load domains file:', err.message);
    process.exit(1);
  }
} else {
  console.error(`✗ ${DOMAINS_FILE} not found`);
  process.exit(1);
}

// ─── Helpers: File I/O ────────────────────────────────────────────────────────
function readJSON(filePath, fallback = {}) {
  try {
    if (fs.existsSync(filePath)) return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_) {}
  return fallback;
}

function writeJSON(filePath, data) {
  try { fs.writeFileSync(filePath, JSON.stringify(data, null, 2)); } catch (_) {}
}

// ─── In-Memory Rate Limiter ───────────────────────────────────────────────────
//
//  Strategy: fixed window per identifier.
//  Anonymous IPs   → 50 req / hour  (was: 50/day, reset at midnight — too loose)
//  API key holders → 1 000 req / hour
//
//  Stored as a plain Map; no disk I/O on every request.
//  Garbage-collected every 10 minutes to keep memory flat.

const ANON_LIMIT    = parseInt(process.env.ANON_RATE_LIMIT,  10) || 50;
const KEY_LIMIT     = parseInt(process.env.KEY_RATE_LIMIT,   10) || 1000;
const WINDOW_MS     = 60 * 60 * 1000; // 1 hour

/** @type {Map<string, { count: number, resetAt: number }>} */
const rateLimitStore = new Map();

// Prune expired windows every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [id, rec] of rateLimitStore) {
    if (now >= rec.resetAt) rateLimitStore.delete(id);
  }
}, 10 * 60 * 1000).unref();

function rateLimiter(req, res, next) {
  const apiKey    = req.headers['x-api-key'];
  const identifier = apiKey || req.ip;
  const limit      = apiKey ? KEY_LIMIT : ANON_LIMIT;
  const now        = Date.now();

  let rec = rateLimitStore.get(identifier);

  // Start a fresh window if none exists or the old one has expired
  if (!rec || now >= rec.resetAt) {
    rec = { count: 0, resetAt: now + WINDOW_MS };
    rateLimitStore.set(identifier, rec);
  }

  const remaining = Math.max(0, limit - rec.count);
  const resetSecs = Math.ceil((rec.resetAt - now) / 1000);

  // Always set informational headers (RFC 6585 / common practice)
  res.set('X-RateLimit-Limit',     String(limit));
  res.set('X-RateLimit-Remaining', String(remaining));
  res.set('X-RateLimit-Reset',     String(Math.ceil(rec.resetAt / 1000)));  // Unix epoch

  if (rec.count >= limit) {
    res.set('Retry-After', String(resetSecs));
    return res.status(429).json({
      status  : 'error',
      code    : 'RATE_LIMIT_EXCEEDED',
      message : `Rate limit of ${limit} requests/hour exceeded. Resets in ${Math.ceil(resetSecs / 60)} minute(s).`,
      retry_after_seconds: resetSecs,
      reset_at: new Date(rec.resetAt).toISOString()
    });
  }

  rec.count++;
  req.rateRemaining = limit - rec.count;
  req.rateLimitKey  = identifier;
  next();
}

// ─── API Key Auth ─────────────────────────────────────────────────────────────
function resolveApiKey(req, res, next) {
  const keyHeader = req.headers['x-api-key'];
  if (!keyHeader) return next();

  const keys      = readJSON(API_KEYS_FILE, { keys: [] });
  const keyRecord = keys.keys.find(k => k.key === keyHeader && k.active);
  if (!keyRecord) {
    return res.status(401).json({
      status : 'error',
      code   : 'INVALID_API_KEY',
      message: 'The provided API key is invalid or revoked.'
    });
  }

  req.apiKeyRecord       = keyRecord;
  keyRecord.lastUsed     = new Date().toISOString();
  keyRecord.requestCount = (keyRecord.requestCount || 0) + 1;
  writeJSON(API_KEYS_FILE, keys);
  next();
}

// ─── Analytics ────────────────────────────────────────────────────────────────
function recordAnalytic(event) {
  const analytics = readJSON(ANALYTICS_FILE, {
    total: 0, disposable: 0, valid: 0, errors: 0, daily: {}, topDomains: {}
  });
  const today = new Date().toISOString().slice(0, 10);

  analytics.total             = (analytics.total || 0) + 1;
  analytics[event.result]     = (analytics[event.result] || 0) + 1;
  analytics.daily[today]      = analytics.daily[today] || { total: 0, disposable: 0, valid: 0 };
  analytics.daily[today].total++;
  if (event.result !== 'errors') analytics.daily[today][event.result]++;
  if (event.domain) {
    analytics.topDomains[event.domain] = (analytics.topDomains[event.domain] || 0) + 1;
  }

  // Keep only last 30 days
  const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  for (const day of Object.keys(analytics.daily)) {
    if (day < cutoff) delete analytics.daily[day];
  }

  writeJSON(ANALYTICS_FILE, analytics);
}

// ─── MX / DNS Validation ─────────────────────────────────────────────────────
async function checkMXRecords(domain) {
  try {
    const records = await dns.resolveMx(domain);
    const hasMX   = records && records.length > 0;
    const topMX   = hasMX ? records.sort((a, b) => a.priority - b.priority)[0].exchange : null;
    return { hasMX, mxRecords: records || [], topMX };
  } catch (err) {
    if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') {
      return { hasMX: false, mxRecords: [], topMX: null };
    }
    return { hasMX: null, mxRecords: [], topMX: null, dnsError: err.code };
  }
}

async function checkDomainExists(domain) {
  try {
    await dns.resolve(domain);
    return true;
  } catch (_) {
    return false;
  }
}

// ─── Confidence Scoring ───────────────────────────────────────────────────────
//
//  Score 0–100: higher = more likely disposable / invalid.
//
//  Label map:
//    80–100  → very_high   (almost certainly disposable)
//    60–79   → high        (strong indicators)
//    40–59   → medium      (mixed signals — flag for review)
//    20–39   → low         (minor concerns)
//    0–19    → very_low    (looks legitimate)

const CONFIDENCE_WEIGHTS = {
  inDisposableList    : 80,   // primary signal — very strong
  noMX                : 15,   // no mail exchange → can't receive email
  domainNotFound      : 12,   // NXDOMAIN — domain doesn't exist at all
  suspiciousPattern   : 8,    // looks randomly generated
  knownTempMXProvider : 10,   // MX points to a known temp-mail host
  singleCharLocal     : 5,    // local-part is just one character (e.g. a@domain.com)
  excessiveDots       : 4,    // too many dots in the domain
  numericHeavyDomain  : 4,    // domain name is mostly numbers
};

// MX exchanges used exclusively by disposable / forwarding services
const TEMP_MX_SIGNATURES = [
  'guerrillamail', 'mailnull', 'spamgourmet', 'trashmail',
  'yopmail', 'maildrop', 'mailinator', 'sharklasers',
  'guerrillamailblock', 'grr.la', 'spam4.me', 'dispostable',
  'fakeinbox', 'tempinbox', 'throwam.com', 'spamhereplease',
  'mohmal', 'jetable', 'filzmail', 'spamex', 'discard.email',
  'armyspy', 'cuvox', 'dayrep', 'einrot', 'fleckens',
  'gustr', 'rhyta', 'superrito', 'teleworm', 'jourrapide'
];

function isTempMXProvider(topMX) {
  if (!topMX) return false;
  const mx = topMX.toLowerCase();
  return TEMP_MX_SIGNATURES.some(sig => mx.includes(sig));
}

function detectSuspiciousPattern(domain) {
  const name = domain.split('.')[0];
  const looksRandom  = /^[a-z0-9]{12,}$/.test(name) && /\d{4,}/.test(name);
  const tooManyHyphens = (name.match(/-/g) || []).length >= 3;
  return looksRandom || tooManyHyphens;
}

function domainIsNumericHeavy(domain) {
  const name = domain.split('.')[0];
  const digits = (name.match(/\d/g) || []).length;
  return name.length > 4 && digits / name.length >= 0.6;
}

function domainHasExcessiveDots(domain) {
  return (domain.match(/\./g) || []).length >= 4;
}

/**
 * @param {object} flags
 * @param {boolean}      flags.inDisposableList
 * @param {boolean}      flags.domainExists
 * @param {boolean|null} flags.hasMX
 * @param {string|null}  flags.topMX
 * @param {boolean}      flags.suspiciousPattern
 * @param {string}       [flags.localPart]
 * @param {string}       [flags.domain]
 * @returns {{ score: number, label: string, reasons: string[] }}
 */
function computeConfidence(flags) {
  let score   = 0;
  const reasons = [];

  if (flags.inDisposableList) {
    score += CONFIDENCE_WEIGHTS.inDisposableList;
    reasons.push('Domain is in the known disposable email blocklist');
  }

  if (flags.hasMX === false) {
    score += CONFIDENCE_WEIGHTS.noMX;
    reasons.push('No MX records found — domain cannot receive email');
  }

  if (flags.domainExists === false) {
    score += CONFIDENCE_WEIGHTS.domainNotFound;
    reasons.push('Domain does not resolve (NXDOMAIN)');
  }

  if (flags.suspiciousPattern) {
    score += CONFIDENCE_WEIGHTS.suspiciousPattern;
    reasons.push('Domain name matches suspicious pattern (random chars or excessive hyphens)');
  }

  if (isTempMXProvider(flags.topMX)) {
    score += CONFIDENCE_WEIGHTS.knownTempMXProvider;
    reasons.push(`MX record points to a known temporary-mail provider (${flags.topMX})`);
  }

  if (flags.localPart && flags.localPart.length === 1) {
    score += CONFIDENCE_WEIGHTS.singleCharLocal;
    reasons.push('Local part (before @) is a single character — unusual for real accounts');
  }

  if (flags.domain && domainHasExcessiveDots(flags.domain)) {
    score += CONFIDENCE_WEIGHTS.excessiveDots;
    reasons.push('Domain has an unusually high number of sub-labels');
  }

  if (flags.domain && domainIsNumericHeavy(flags.domain)) {
    score += CONFIDENCE_WEIGHTS.numericHeavyDomain;
    reasons.push('Domain name is predominantly numeric — uncommon for legitimate providers');
  }

  // Legitimacy deductions (only when not already blocklisted)
  if (!flags.inDisposableList) {
    if (flags.hasMX)          score = Math.max(0, score - 10);
    if (flags.domainExists)   score = Math.max(0, score - 5);
  }

  const capped = Math.min(score, 100);

  let label;
  if      (capped >= 80) label = 'very_high';
  else if (capped >= 60) label = 'high';
  else if (capped >= 40) label = 'medium';
  else if (capped >= 20) label = 'low';
  else                   label = 'very_low';

  return { score: capped, label, reasons };
}

// ─── Webhook Dispatcher ───────────────────────────────────────────────────────
async function dispatchWebhooks(eventType, payload) {
  const webhooks = readJSON(WEBHOOKS_FILE, { hooks: [] });
  const active   = webhooks.hooks.filter(h => h.active && h.events.includes(eventType));
  if (!active.length) return;

  setImmediate(async () => {
    for (const hook of active) {
      try {
        const fetch = require('node-fetch');
        await fetch(hook.url, {
          method : 'POST',
          headers: {
            'Content-Type'     : 'application/json',
            'X-Webhook-Event'  : eventType,
            'X-Webhook-Secret' : hook.secret || '',
            'X-Delivery-ID'    : uuidv4()
          },
          body   : JSON.stringify({ event: eventType, timestamp: new Date().toISOString(), data: payload }),
          timeout: 5000
        });
        hook.lastDelivery  = new Date().toISOString();
        hook.deliveryCount = (hook.deliveryCount || 0) + 1;
      } catch (err) {
        hook.lastError   = err.message;
        hook.lastErrorAt = new Date().toISOString();
      }
    }
    writeJSON(WEBHOOKS_FILE, webhooks);
  });
}

// ─── Email Validation Core ────────────────────────────────────────────────────
async function validateEmail(email, options = {}) {
  const { checkDNS = true } = options;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return { valid: false, error: 'Invalid email format', code: 'INVALID_FORMAT' };
  }

  const [localPart, domain] = email.split('@');
  const domainLower = domain.toLowerCase();

  const inDisposableList  = disposableDomains.has(domainLower);
  const suspiciousPattern = detectSuspiciousPattern(domainLower);

  let domainExists = true;
  let hasMX        = true;
  let mxRecords    = [];
  let topMX        = null;
  let dnsChecked   = false;

  if (checkDNS) {
    dnsChecked = true;
    [domainExists, { hasMX, mxRecords, topMX }] = await Promise.all([
      checkDomainExists(domainLower),
      checkMXRecords(domainLower)
    ]);
  }

  const { score, label, reasons } = computeConfidence({
    inDisposableList,
    domainExists,
    hasMX,
    topMX,
    suspiciousPattern,
    localPart,
    domain: domainLower
  });

  // Verdict thresholds
  let verdict, status;
  if      (score >= 60) { verdict = 'disposable'; status = 'invalid'; }
  else if (score >= 30) { verdict = 'suspicious'; status = 'risky'; }
  else                  { verdict = 'legitimate'; status = 'valid'; }

  return {
    status,
    verdict,
    email,
    domain       : domainLower,
    local_part   : localPart,
    is_disposable: inDisposableList,
    confidence   : {
      score,
      label,    // very_low | low | medium | high | very_high
    },
    // Keep top-level field for backwards-compat
    confidence_score: score,
    risk_level      : score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low',
    reasons,
    dns: dnsChecked ? {
      domain_exists: domainExists,
      has_mx       : hasMX,
      mx_records   : mxRecords.map(r => ({ priority: r.priority, exchange: r.exchange })),
      primary_mx   : topMX
    } : null,
    checks: {
      in_blocklist      : inDisposableList,
      suspicious_pattern: suspiciousPattern,
      dns_checked       : dnsChecked
    },
    checked_at: new Date().toISOString()
  };
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Single email verify
app.post('/v1/verify', resolveApiKey, rateLimiter, async (req, res) => {
  const { email, check_dns = true } = req.body;

  if (!email || typeof email !== 'string') {
    return res.status(400).json({
      status : 'error',
      code   : 'MISSING_EMAIL',
      message: 'Provide an email string in the request body.'
    });
  }

  try {
    const result = await validateEmail(email.trim(), { checkDNS: check_dns });
    result.rate_limit = { remaining: req.rateRemaining };

    recordAnalytic({ result: result.is_disposable ? 'disposable' : 'valid', domain: result.domain });

    if (result.is_disposable || result.verdict === 'suspicious') {
      dispatchWebhooks('disposable.detected', { email, result });
    }

    res.status(200).json(result);
  } catch (err) {
    console.error('Verify error:', err);
    recordAnalytic({ result: 'errors' });
    res.status(500).json({ status: 'error', code: 'INTERNAL_ERROR', message: 'Verification failed.' });
  }
});

// Bulk verify (up to 50 emails)
app.post('/v1/verify/bulk', resolveApiKey, rateLimiter, async (req, res) => {
  const { emails, check_dns = false } = req.body;

  if (!Array.isArray(emails) || emails.length === 0) {
    return res.status(400).json({
      status : 'error',
      code   : 'MISSING_EMAILS',
      message: 'Provide an array of email strings.'
    });
  }
  if (emails.length > 50) {
    return res.status(400).json({
      status : 'error',
      code   : 'TOO_MANY_EMAILS',
      message: 'Bulk endpoint accepts up to 50 emails per request.'
    });
  }

  try {
    const results = await Promise.all(
      emails.map(email =>
        validateEmail(typeof email === 'string' ? email.trim() : '', { checkDNS: check_dns })
      )
    );

    const summary = {
      total  : results.length,
      valid  : results.filter(r => r.status === 'valid').length,
      invalid: results.filter(r => r.status === 'invalid').length,
      risky  : results.filter(r => r.status === 'risky').length,
    };

    results.forEach(r =>
      recordAnalytic({ result: r.is_disposable ? 'disposable' : 'valid', domain: r.domain })
    );

    dispatchWebhooks('bulk.complete', { summary });

    res.status(200).json({ status: 'ok', summary, results });
  } catch (err) {
    console.error('Bulk verify error:', err);
    res.status(500).json({ status: 'error', code: 'INTERNAL_ERROR', message: 'Bulk verification failed.' });
  }
});

// Domain check (without local part)
app.get('/v1/domain/:domain', resolveApiKey, rateLimiter, async (req, res) => {
  const domain = req.params.domain.toLowerCase().trim();
  if (!domain || !domain.includes('.')) {
    return res.status(400).json({ status: 'error', code: 'INVALID_DOMAIN', message: 'Provide a valid domain.' });
  }

  try {
    const inList = disposableDomains.has(domain);
    const [domainExists, mxInfo] = await Promise.all([
      checkDomainExists(domain),
      checkMXRecords(domain)
    ]);

    const { score, label, reasons } = computeConfidence({
      inDisposableList  : inList,
      domainExists,
      hasMX             : mxInfo.hasMX,
      topMX             : mxInfo.topMX,
      suspiciousPattern : detectSuspiciousPattern(domain),
      domain
    });

    res.status(200).json({
      status      : 'ok',
      domain,
      is_disposable: inList,
      confidence  : { score, label },
      confidence_score: score,        // backwards-compat
      risk_level  : score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low',
      reasons,
      dns: {
        domain_exists: domainExists,
        has_mx       : mxInfo.hasMX,
        mx_records   : mxInfo.mxRecords.map(r => ({ priority: r.priority, exchange: r.exchange })),
        primary_mx   : mxInfo.topMX
      },
      checked_at: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ status: 'error', code: 'INTERNAL_ERROR', message: 'Domain check failed.' });
  }
});

// Analytics
app.get('/v1/analytics', resolveApiKey, (req, res) => {
  const analytics = readJSON(ANALYTICS_FILE, {
    total: 0, disposable: 0, valid: 0, errors: 0, daily: {}, topDomains: {}
  });

  const topDomains = Object.entries(analytics.topDomains || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([domain, count]) => ({ domain, count }));

  const trend = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date(Date.now() - i * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    trend.push({ date: d, ...(analytics.daily[d] || { total: 0, disposable: 0, valid: 0 }) });
  }

  res.json({
    status : 'ok',
    summary: {
      total_checks    : analytics.total     || 0,
      total_disposable: analytics.disposable || 0,
      total_valid     : analytics.valid      || 0,
      total_errors    : analytics.errors     || 0,
      disposable_rate : analytics.total
        ? ((analytics.disposable / analytics.total) * 100).toFixed(1) + '%'
        : '0%'
    },
    trend,
    top_domains: topDomains
  });
});

// Rate-limit status (handy for debugging / dashboards)
app.get('/v1/rate-limit/status', resolveApiKey, (req, res) => {
  const apiKey     = req.headers['x-api-key'];
  const identifier = apiKey || req.ip;
  const limit      = apiKey ? KEY_LIMIT : ANON_LIMIT;
  const now        = Date.now();
  const rec        = rateLimitStore.get(identifier);

  if (!rec || now >= rec.resetAt) {
    return res.json({
      status   : 'ok',
      identifier: identifier,
      limit,
      used     : 0,
      remaining: limit,
      reset_at : new Date(now + WINDOW_MS).toISOString()
    });
  }

  res.json({
    status    : 'ok',
    identifier,
    limit,
    used      : rec.count,
    remaining : Math.max(0, limit - rec.count),
    reset_at  : new Date(rec.resetAt).toISOString()
  });
});

// Webhook management
app.get('/v1/webhooks', resolveApiKey, (req, res) => {
  const data = readJSON(WEBHOOKS_FILE, { hooks: [] });
  res.json({ status: 'ok', webhooks: data.hooks.map(h => ({ ...h, secret: h.secret ? '***' : null })) });
});

app.post('/v1/webhooks', resolveApiKey, (req, res) => {
  const { url, events, secret } = req.body;
  if (!url || !events || !Array.isArray(events)) {
    return res.status(400).json({ status: 'error', message: 'Provide url and events array.' });
  }

  const validEvents   = ['disposable.detected', 'bulk.complete'];
  const invalidEvents = events.filter(e => !validEvents.includes(e));
  if (invalidEvents.length) {
    return res.status(400).json({
      status : 'error',
      message: `Invalid events: ${invalidEvents.join(', ')}. Valid: ${validEvents.join(', ')}`
    });
  }

  const data = readJSON(WEBHOOKS_FILE, { hooks: [] });
  const hook = {
    id           : uuidv4(),
    url,
    events,
    secret       : secret || null,
    active       : true,
    createdAt    : new Date().toISOString(),
    deliveryCount: 0
  };
  data.hooks.push(hook);
  writeJSON(WEBHOOKS_FILE, data);

  res.status(201).json({ status: 'ok', webhook: { ...hook, secret: secret ? '***' : null } });
});

app.delete('/v1/webhooks/:id', resolveApiKey, (req, res) => {
  const data = readJSON(WEBHOOKS_FILE, { hooks: [] });
  const idx  = data.hooks.findIndex(h => h.id === req.params.id);
  if (idx === -1) return res.status(404).json({ status: 'error', message: 'Webhook not found.' });
  data.hooks.splice(idx, 1);
  writeJSON(WEBHOOKS_FILE, data);
  res.json({ status: 'ok', message: 'Webhook deleted.' });
});

// API Key provisioning (admin-only via env secret)
app.post('/v1/keys', (req, res) => {
  const adminSecret = process.env.ADMIN_SECRET;
  if (!adminSecret || req.headers['x-admin-secret'] !== adminSecret) {
    return res.status(403).json({ status: 'error', message: 'Forbidden.' });
  }

  const { name, notes } = req.body;
  const data    = readJSON(API_KEYS_FILE, { keys: [] });
  const newKey  = {
    id          : uuidv4(),
    key         : `ek_live_${uuidv4().replace(/-/g, '')}`,
    name        : name  || 'Unnamed key',
    notes       : notes || '',
    active      : true,
    createdAt   : new Date().toISOString(),
    lastUsed    : null,
    requestCount: 0
  };
  data.keys.push(newKey);
  writeJSON(API_KEYS_FILE, data);

  res.status(201).json({ status: 'ok', api_key: newKey });
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status         : 'ok',
    version        : '2.1.0',
    domains_loaded : disposableDomains.size,
    uptime_seconds : Math.floor(process.uptime()),
    rate_limit     : { anon: ANON_LIMIT, key: KEY_LIMIT, window: '1h' },
    timestamp      : new Date().toISOString()
  });
});

// Catch-all → serve frontend
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🚀 Email Validator API v2.1 running on port ${PORT}`);
  console.log(`   Domains loaded : ${disposableDomains.size}`);
  console.log(`   Rate limits    : ${ANON_LIMIT} req/h (anon) · ${KEY_LIMIT} req/h (key)`);
  console.log(`   Health         : http://localhost:${PORT}/health\n`);
});
