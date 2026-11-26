export interface PhishingFlag {
  id: string;
  label: string;
  description: string;
  triggered: boolean;
  severity: "high" | "medium" | "low";
  value?: string;
}

export interface DetectionResult {
  url: string;
  score: number; // 0-100, higher = more likely phishing
  verdict: "safe" | "suspicious" | "dangerous";
  flags: PhishingFlag[];
  parsedUrl: {
    protocol: string;
    hostname: string;
    path: string;
    port: string;
  } | null;
}

const HIGH_SEVERITY_WEIGHT = 25;
const MEDIUM_SEVERITY_WEIGHT = 12;
const LOW_SEVERITY_WEIGHT = 5;

function safeParseUrl(input: string): URL | null {
  const normalized = input.trim();
  if (!normalized) return null;
  try {
    return new URL(normalized.startsWith("http") ? normalized : `https://${normalized}`);
  } catch {
    return null;
  }
}

const SHORTENERS = [
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
  "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st",
  "tiny.cc", "soo.gd", "rb.gy", "lnkd.in", "shorturl.at",
];

const SUSPICIOUS_TLDS = [
  ".zip", ".mov", ".xyz", ".top", ".tk", ".ml", ".ga", ".cf",
  ".gq", ".cn", ".ru", ".su", ".country", ".kim", ".science",
  ".work", ".click", ".link", ".country",
];

const TRUSTED_DOMAINS = [
  "google.com", "youtube.com", "facebook.com", "amazon.com",
  "microsoft.com", "apple.com", "github.com", "linkedin.com",
  "twitter.com", "instagram.com", "wikipedia.org", "wikipedia.com",
  "reddit.com", "netflix.com", "gmail.com", "outlook.com",
  "office.com", "live.com", "yahoo.com", "paypal.com",
  "stackoverflow.com", "w3.org", "mozilla.org",
];

function levenshtein(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1,
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

function extractRegistrableDomain(hostname: string): string {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join(".");
}

export function analyzeUrl(rawUrl: string): DetectionResult | null {
  const parsed = safeParseUrl(rawUrl);
  if (!parsed) return null;

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl = parsed.href;
  const registrable = extractRegistrableDomain(hostname);

  const flags: PhishingFlag[] = [];

  // 1. IP address in hostname
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Pattern = /^\[?[0-9a-f:]+\]?$/i;
  flags.push({
    id: "ip-host",
    label: "IP address used as hostname",
    description: "Legitimate websites almost always use domain names, not raw IP addresses. Phishing sites often use IPs to hide ownership.",
    triggered: ipv4Pattern.test(hostname) || (hostname.startsWith("[") && ipv6Pattern.test(hostname)),
    severity: "high",
    value: hostname,
  });

  // 2. URL length
  flags.push({
    id: "url-length",
    label: "Excessively long URL",
    description: "Very long URLs (over 75 characters) are often used to hide the real destination or encode tracking/redirect parameters.",
    triggered: fullUrl.length > 75,
    severity: "medium",
    value: `${fullUrl.length} chars`,
  });

  // 3. @ symbol in URL
  flags.push({
    id: "at-symbol",
    label: "@ symbol in URL",
    description: "The @ symbol causes the browser to ignore everything before it, making 'https://google.com@evil.com' actually visit evil.com.",
    triggered: fullUrl.includes("@"),
    severity: "high",
  });

  // 4. Too many subdomains
  const subdomainParts = hostname.split(".").slice(0, -2);
  flags.push({
    id: "subdomains",
    label: "Excessive subdomains",
    description: "Many subdomains (4+) can indicate an attempt to mimic a legitimate domain by burying the real domain deep in the hierarchy.",
    triggered: subdomainParts.length >= 4,
    severity: "medium",
    value: `${subdomainParts.length} subdomain levels`,
  });

  // 5. Hyphen count in hostname
  const hyphenCount = (hostname.match(/-/g) || []).length;
  flags.push({
    id: "hyphens",
    label: "Many hyphens in domain",
    description: "Multiple hyphens (e.g., 'secure-login-paypal-com') are a common tactic to imitate trusted brand names.",
    triggered: hyphenCount >= 3,
    severity: "medium",
    value: `${hyphenCount} hyphens`,
  });

  // 6. Suspicious TLD
  const suspiciousTld = SUSPICIOUS_TLDS.some((tld) => hostname.endsWith(tld));
  flags.push({
    id: "suspicious-tld",
    label: "Suspicious top-level domain",
    description: "Certain TLDs (.zip, .xyz, .tk, .top, etc.) are frequently abused for phishing because they are cheap or free to register.",
    triggered: suspiciousTld,
    severity: "medium",
    value: hostname.split(".").pop(),
  });

  // 7. Not HTTPS
  flags.push({
    id: "no-https",
    label: "No HTTPS encryption",
    description: "Legitimate sites that handle user data use HTTPS. An HTTP-only connection means data is sent unencrypted.",
    triggered: parsed.protocol !== "https:",
    severity: "medium",
  });

  // 8. URL shortener
  const isShortened = SHORTENERS.some((s) => hostname === s || hostname.endsWith(`.${s}`));
  flags.push({
    id: "shortener",
    label: "URL shortener used",
    description: "Shortened URLs hide the real destination. While not always malicious, they are frequently used in phishing to disguise links.",
    triggered: isShortened,
    severity: "low",
    value: hostname,
  });

  // 9. Non-standard port
  flags.push({
    id: "port",
    label: "Non-standard port number",
    description: "Standard web traffic uses port 80 (HTTP) or 443 (HTTPS). Other ports can indicate a service running outside normal expectations.",
    triggered: parsed.port !== "" && parsed.port !== "80" && parsed.port !== "443",
    severity: "low",
    value: parsed.port,
  });

  // 10. Embedding / redirect keywords
  const redirectKeywords = ["redirect", "redirecturl", "url=", "next=", "goto=", "return=", "continue=", "dest=", "destination="];
  const hasRedirect = redirectKeywords.some((kw) => fullUrl.toLowerCase().includes(kw));
  flags.push({
    id: "redirect",
    label: "Open redirect parameter",
    description: "Redirect parameters in a URL can be abused to bounce a user from a legitimate-looking site to a phishing page.",
    triggered: hasRedirect,
    severity: "medium",
  });

  // 11. Punycode / IDN homograph
  const hasPunycode = hostname.includes("xn--");
  flags.push({
    id: "punycode",
    label: "Punycode (internationalized) domain",
    description: "Punycode domains can display as lookalike characters (e.g., аpple.com using a Cyrillic 'а'), a classic homograph attack technique.",
    triggered: hasPunycode,
    severity: "high",
  });

  // 12. Typosquatting — close to a trusted domain
  let typoTarget: string | null = null;
  for (const trusted of TRUSTED_DOMAINS) {
    if (registrable === trusted) {
      typoTarget = null;
      break;
    }
    const dist = levenshtein(registrable, trusted);
    if (dist > 0 && dist <= 2 && Math.abs(registrable.length - trusted.length) <= 2) {
      typoTarget = trusted;
      break;
    }
  }
  flags.push({
    id: "typosquat",
    label: "Looks like a trusted domain (typosquatting)",
    description: `This domain is very similar to "${typoTarget}" with only small spelling differences — a common phishing technique called typosquatting.`,
    triggered: typoTarget !== null,
    severity: "high",
    value: typoTarget ? `similar to ${typoTarget}` : undefined,
  });

  // 13. Suspicious characters
  const suspiciousChars = ["%", "//", "~", "!", "$", "*"];
  const charHits = suspiciousChars.filter((c) => parsed.pathname.includes(c) || parsed.search.includes(c));
  flags.push({
    id: "special-chars",
    label: "Unusual special characters in path",
    description: "Characters like %, //, ~, and $ in the path can be used to obfuscate the real destination or exploit parsing quirks.",
    triggered: charHits.length >= 2,
    severity: "low",
    value: charHits.join(", "),
  });

  // 14. Double slash in path (after protocol)
  const pathDoubleSlash = parsed.pathname.includes("//") || parsed.search.includes("//");
  flags.push({
    id: "double-slash",
    label: "Double slash in path",
    description: "Extra slashes in the path can confuse URL parsers and hide the real resource being loaded.",
    triggered: pathDoubleSlash,
    severity: "low",
  });

  // 15. Hex or encoded characters in hostname
  const hasEncodedHostname = /%[0-9a-f]{2}/i.test(hostname);
  flags.push({
    id: "encoded-host",
    label: "Encoded characters in hostname",
    description: "Percent-encoded characters in the hostname are abnormal and can be used to disguise the actual domain.",
    triggered: hasEncodedHostname,
    severity: "medium",
  });

  // Calculate score
  let score = 0;
  for (const flag of flags) {
    if (flag.triggered) {
      if (flag.severity === "high") score += HIGH_SEVERITY_WEIGHT;
      else if (flag.severity === "medium") score += MEDIUM_SEVERITY_WEIGHT;
      else score += LOW_SEVERITY_WEIGHT;
    }
  }
  // Trusted domain bonus — reduce score
  if (TRUSTED_DOMAINS.includes(registrable)) {
    score = Math.max(0, score - 20);
  }
  score = Math.min(100, score);

  let verdict: DetectionResult["verdict"] = "safe";
  if (score >= 40) verdict = "dangerous";
  else if (score >= 15) verdict = "suspicious";

  return {
    url: fullUrl,
    score,
    verdict,
    flags,
    parsedUrl: {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      port: parsed.port,
    },
  };
}

export function verdictLabel(verdict: DetectionResult["verdict"]): string {
  if (verdict === "dangerous") return "Likely Phishing";
  if (verdict === "suspicious") return "Suspicious";
  return "Appears Safe";
}
