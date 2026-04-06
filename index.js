const express = require("express");
const dns = require("dns").promises;

const app = express();
app.use(express.json());

// ─── Security: RapidAPI Proxy Secret ───────────────────────────────────────
const RAPIDAPI_SECRET = process.env.RAPIDAPI_PROXY_SECRET;

function checkSecret(req, res, next) {
  if (RAPIDAPI_SECRET) {
    const incoming = req.headers["x-rapidapi-proxy-secret"];
    if (!incoming || incoming !== RAPIDAPI_SECRET) {
      return res.status(403).json({ error: "Forbidden: invalid proxy secret" });
    }
  }
  next();
}

// ─── Disposable email domains list ─────────────────────────────────────────
const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
  "throwaway.email", "yopmail.com", "sharklasers.com", "guerrillamailblock.com",
  "grr.la", "guerrillamail.info", "guerrillamail.biz", "guerrillamail.de",
  "guerrillamail.net", "guerrillamail.org", "spam4.me", "trashmail.com",
  "trashmail.me", "trashmail.net", "trashmail.at", "trashmail.io",
  "dispostable.com", "fakeinbox.com", "mailnull.com", "spamgourmet.com",
  "spamgourmet.net", "spamgourmet.org", "maildrop.cc", "discard.email",
  "tempr.email", "mailtemp.info", "tempail.com", "getnada.com",
  "mohmal.com", "mailnesia.com", "tempomail.fr", "mytemp.email",
  "temp-mail.org", "temp-mail.ru", "temp-mail.io", "tmpmail.net",
  "tmpmail.org", "zetmail.com", "wegwerfmail.de", "wegwerfmail.net",
  "wegwerfmail.org", "sogetthis.com", "spamhereplease.com", "spamthisplease.com",
  "binkmail.com", "bobmail.info", "chammy.info", "devnullmail.com",
  "letthemeatspam.com", "mailinater.com", "smellfear.com", "spamgob.com",
  "thisisnotmyrealemail.com", "uggsrock.com", "throwam.com", "mailscrap.com",
  "mailexpire.com", "spamevader.com", "spaml.de", "spaml.com",
  "fixmail.tk", "filzmail.com", "spam.la", "spamoff.de",
  "temporaryemail.net", "temporaryemail.us", "tempinbox.com", "tempinbox.co.uk",
  "deadaddress.com", "emailondeck.com", "incognitomail.com", "incognitomail.net",
  "incognitomail.org", "mailnew.com", "notsharingmy.info", "nowmymail.net",
  "pokemail.net", "reallymymail.com", "smellfear.com", "snakemail.com",
  "supermailer.jp", "suremail.info", "teleworm.us", "the-cloak.com",
  "trbvm.com", "turual.com", "uroid.com", "veryrealemail.com",
  "viditag.com", "webemail.me", "xemaps.com", "xsmail.com",
  "yuurok.com", "zehnminuten.de", "zehnminutenmail.de", "zoemail.net",
  "crazymailing.com", "cool.fr.nf", "courriel.fr.nf", "lol.ovpn.to",
  "spamstack.net", "superrito.com", "suremail.info", "teleworm.us"
]);

// ─── Free email providers ───────────────────────────────────────────────────
const FREE_PROVIDERS = new Set([
  "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.fr",
  "yahoo.es", "yahoo.de", "yahoo.it", "yahoo.com.br", "hotmail.com",
  "hotmail.co.uk", "hotmail.fr", "hotmail.de", "hotmail.it", "hotmail.es",
  "outlook.com", "outlook.fr", "outlook.de", "outlook.it", "outlook.es",
  "live.com", "live.co.uk", "live.fr", "live.de", "msn.com",
  "icloud.com", "me.com", "mac.com", "aol.com", "protonmail.com",
  "proton.me", "pm.me", "zoho.com", "mail.com", "email.com",
  "gmx.com", "gmx.de", "gmx.net", "web.de", "t-online.de",
  "orange.fr", "wanadoo.fr", "free.fr", "laposte.net", "bbox.fr",
  "yandex.com", "yandex.ru", "mail.ru", "rambler.ru", "inbox.ru",
  "tutanota.com", "fastmail.com", "hushmail.com", "mailfence.com"
]);

// ─── Role-based prefixes ────────────────────────────────────────────────────
const ROLE_PREFIXES = new Set([
  "admin", "administrator", "webmaster", "hostmaster", "postmaster",
  "info", "support", "help", "helpdesk", "contact", "sales", "marketing",
  "billing", "accounts", "accounting", "finance", "hr", "jobs",
  "careers", "recruiter", "recruiting", "noreply", "no-reply", "no_reply",
  "donotreply", "do-not-reply", "bounce", "bounces", "spam", "abuse",
  "security", "press", "media", "newsletter", "notifications", "alerts",
  "team", "office", "legal", "compliance", "privacy", "data"
]);

// ─── Syntax validation (RFC 5322 simplified) ───────────────────────────────
function validateSyntax(email) {
  if (!email || typeof email !== "string") return false;
  if (email.length > 254) return false;
  const regex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
  if (!regex.test(email)) return false;
  const [local, domain] = email.split("@");
  if (local.length > 64) return false;
  if (local.startsWith(".") || local.endsWith(".")) return false;
  if (local.includes("..")) return false;
  return true;
}

// ─── MX record check ───────────────────────────────────────────────────────
async function checkMX(domain) {
  try {
    const records = await dns.resolveMx(domain);
    if (records && records.length > 0) {
      // Sort by priority (lower = higher priority)
      records.sort((a, b) => a.priority - b.priority);
      return { found: true, records: records.map(r => r.exchange) };
    }
    return { found: false, records: [] };
  } catch {
    return { found: false, records: [] };
  }
}

// ─── Domain A record check (domain exists at all?) ────────────────────────
async function checkDomainExists(domain) {
  try {
    await dns.resolve(domain);
    return true;
  } catch {
    try {
      await dns.resolve4(domain);
      return true;
    } catch {
      return false;
    }
  }
}

// ─── Score calculator ──────────────────────────────────────────────────────
function calculateScore(checks) {
  let score = 100;
  if (!checks.syntax_valid)     score -= 60;
  if (!checks.domain_exists)    score -= 30;
  if (!checks.mx_found)         score -= 20;
  if (checks.is_disposable)     score -= 40;
  if (checks.is_role_based)     score -= 10;
  return Math.max(0, Math.min(100, score));
}

// ─── Status from score ─────────────────────────────────────────────────────
function getStatus(score, checks) {
  if (!checks.syntax_valid || !checks.domain_exists || !checks.mx_found) {
    return "invalid";
  }
  if (checks.is_disposable) return "invalid";
  if (score >= 70) return "valid";
  if (score >= 40) return "risky";
  return "invalid";
}

// ─── Health check ──────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({
    service: "Email Validator API",
    status: "online",
    version: "1.0.0",
    endpoints: {
      validate: "POST /validate-email",
      bulk: "POST /validate-bulk"
    }
  });
});

// ─── Single email validation ───────────────────────────────────────────────
app.post("/validate-email", checkSecret, async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      success: false,
      error: "Missing 'email' field in request body"
    });
  }

  const emailStr = String(email).trim().toLowerCase();
  const syntaxValid = validateSyntax(emailStr);

  if (!syntaxValid) {
    return res.json({
      success: true,
      email: emailStr,
      score: 0,
      status: "invalid",
      checks: {
        syntax_valid: false,
        domain_exists: false,
        mx_found: false,
        is_disposable: false,
        is_free_provider: false,
        is_role_based: false
      },
      mx_records: [],
      provider: null,
      suggestion: null
    });
  }

  const [local, domain] = emailStr.split("@");

  // Run DNS checks in parallel for speed
  const [domainExists, mxResult] = await Promise.all([
    checkDomainExists(domain),
    checkMX(domain)
  ]);

  const isDisposable = DISPOSABLE_DOMAINS.has(domain);
  const isFreeProvider = FREE_PROVIDERS.has(domain);
  const isRoleBased = ROLE_PREFIXES.has(local.split("+")[0].split(".")[0]);

  // Typo suggestion for common providers
  let suggestion = null;
  const commonDomains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com"];
  for (const common of commonDomains) {
    if (domain !== common && levenshtein(domain, common) <= 2) {
      suggestion = emailStr.replace(domain, common);
      break;
    }
  }

  const checks = {
    syntax_valid: true,
    domain_exists: domainExists,
    mx_found: mxResult.found,
    is_disposable: isDisposable,
    is_free_provider: isFreeProvider,
    is_role_based: isRoleBased
  };

  const score = calculateScore(checks);
  const status = getStatus(score, checks);

  return res.json({
    success: true,
    email: emailStr,
    score,
    status,
    checks,
    mx_records: mxResult.records.slice(0, 3),
    provider: isFreeProvider ? domain : (isDisposable ? "disposable" : "custom/business"),
    suggestion
  });
});

// ─── Bulk email validation (max 10 per request on free tier) ───────────────
app.post("/validate-bulk", checkSecret, async (req, res) => {
  const { emails } = req.body;

  if (!emails || !Array.isArray(emails)) {
    return res.status(400).json({
      success: false,
      error: "Missing 'emails' array in request body"
    });
  }

  if (emails.length > 10) {
    return res.status(400).json({
      success: false,
      error: "Maximum 10 emails per bulk request. Upgrade for higher limits."
    });
  }

  if (emails.length === 0) {
    return res.status(400).json({
      success: false,
      error: "'emails' array cannot be empty"
    });
  }

  // Process in parallel
  const results = await Promise.all(
    emails.map(async (email) => {
      const emailStr = String(email).trim().toLowerCase();
      const syntaxValid = validateSyntax(emailStr);

      if (!syntaxValid) {
        return {
          email: emailStr,
          score: 0,
          status: "invalid",
          checks: {
            syntax_valid: false,
            domain_exists: false,
            mx_found: false,
            is_disposable: false,
            is_free_provider: false,
            is_role_based: false
          }
        };
      }

      const [local, domain] = emailStr.split("@");
      const [domainExists, mxResult] = await Promise.all([
        checkDomainExists(domain),
        checkMX(domain)
      ]);

      const checks = {
        syntax_valid: true,
        domain_exists: domainExists,
        mx_found: mxResult.found,
        is_disposable: DISPOSABLE_DOMAINS.has(domain),
        is_free_provider: FREE_PROVIDERS.has(domain),
        is_role_based: ROLE_PREFIXES.has(local.split("+")[0].split(".")[0])
      };

      const score = calculateScore(checks);
      return {
        email: emailStr,
        score,
        status: getStatus(score, checks),
        checks
      };
    })
  );

  const summary = {
    total: results.length,
    valid: results.filter(r => r.status === "valid").length,
    risky: results.filter(r => r.status === "risky").length,
    invalid: results.filter(r => r.status === "invalid").length
  };

  return res.json({
    success: true,
    summary,
    results
  });
});

// ─── Levenshtein distance (typo detection) ─────────────────────────────────
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

// ─── Start server ──────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Email Validator API running on port ${PORT}`);
});
