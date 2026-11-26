import { useState, useCallback, useRef, useEffect } from "react";
import { Shield, ShieldAlert, ShieldCheck, Search, ExternalLink, AlertTriangle, Info, CheckCircle2, XCircle, ChevronDown, Lock, Zap, BarChart3, Scan, Code2 } from "lucide-react";
import { analyzeUrl, verdictLabel, type DetectionResult, type PhishingFlag } from "./utils/detector";
import "./App.css";

const EXAMPLES: { label: string; url: string }[] = [
  { label: "Legitimate", url: "https://www.google.com/search?q=safety" },
  { label: "Suspicious", url: "http://secure-login-paypal-verify.com/account/update?id=4491" },
  { label: "Dangerous", url: "http://192.168.4.21/paypal/login.php?redirect=https://paypal.com" },
];

export default function App() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<DetectionResult | null>(null);
  const [error, setError] = useState("");
  const [history, setHistory] = useState<{ url: string; verdict: DetectionResult["verdict"]; score: number }[]>([]);
  const [expandedFlag, setExpandedFlag] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  const handleAnalyze = useCallback((value: string) => {
    const trimmed = value.trim();
    if (!trimmed) {
      setError("Please enter a URL to analyze.");
      setResult(null);
      return;
    }
    setError("");
    setScanning(true);
    setResult(null);

    setTimeout(() => {
      const res = analyzeUrl(trimmed);
      setScanning(false);
      if (!res) {
        setError("Could not parse that URL. Please check the format and try again.");
        return;
      }
      setResult(res);
      setHistory((prev) => [
        { url: res.url, verdict: res.verdict, score: res.score },
        ...prev.filter((h) => h.url !== res.url),
      ].slice(0, 5));
    }, 500);
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleAnalyze(input);
  };

  useEffect(() => {
    if (result && resultRef.current) {
      resultRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [result]);

  const triggeredCount = result?.flags.filter((f) => f.triggered).length ?? 0;
  const passedCount = result ? result.flags.length - triggeredCount : 0;

  return (
    <div className="app">
      <nav className="nav">
        <div className="nav-inner">
          <div className="nav-brand">
            <Shield className="nav-logo" size={26} />
            <span>PhishGuard</span>
          </div>
          <div className="nav-links">
            <a href="#checker">Check URL</a>
            <a href="#how">How It Works</a>
            <a href="#indicators">Indicators</a>
            <a href="https://github.com" target="_blank" rel="noreferrer" className="nav-github">
              <Code2 size={18} />
            </a>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <header className="hero" id="checker">
        <div className="hero-bg" aria-hidden="true" />
        <div className="hero-content">
          <div className="hero-badge">
            <Zap size={14} />
            <span>Real-time in-browser detection</span>
          </div>
          <h1 className="hero-title">
            Spot phishing URLs <span className="hero-accent">before they spot you</span>
          </h1>
          <p className="hero-subtitle">
            Paste any URL and PhishGuard analyzes 15 phishing indicators instantly —
            no data leaves your browser.
          </p>

          {/* Search */}
          <form className="search-form" onSubmit={handleSubmit}>
            <div className={`search-box ${scanning ? "scanning" : ""} ${error ? "error" : ""}`}>
              <Search className="search-icon" size={20} />
              <input
                ref={inputRef}
                type="text"
                placeholder="Paste a URL, e.g. https://example.com/login"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                aria-label="URL to analyze"
              />
              <button type="submit" className="search-btn" disabled={scanning}>
                {scanning ? <Scan className="spin" size={18} /> : "Analyze"}
              </button>
            </div>
            {error && <p className="search-error"><AlertTriangle size={14} /> {error}</p>}
          </form>

          {/* Examples */}
          <div className="examples">
            <span className="examples-label">Try an example:</span>
            {EXAMPLES.map((ex) => (
              <button
                key={ex.url}
                className="example-chip"
                onClick={() => { setInput(ex.url); handleAnalyze(ex.url); }}
              >
                {ex.label}
              </button>
            ))}
          </div>
        </div>
      </header>

      {/* Result */}
      {scanning && (
        <section className="result-section">
          <div className="scanning-card">
            <Scan className="spin big" size={40} />
            <p>Analyzing URL indicators…</p>
          </div>
        </section>
      )}

      {result && !scanning && (
        <section className="result-section" ref={resultRef}>
          <div className={`result-card ${result.verdict}`}>
            <div className="result-header">
              <div className="result-icon-wrap">
                {result.verdict === "safe" && <ShieldCheck size={48} />}
                {result.verdict === "suspicious" && <ShieldAlert size={48} />}
                {result.verdict === "dangerous" && <ShieldAlert size={48} />}
              </div>
              <div className="result-headline">
                <span className="result-verdict">{verdictLabel(result.verdict)}</span>
                <span className="result-url" title={result.url}>
                  {result.parsedUrl?.hostname}
                  <ExternalLink size={13} />
                </span>
              </div>
              <div className="result-score">
                <div className="score-ring" style={{ "--score": `${result.score}` } as React.CSSProperties}>
                  <span>{result.score}</span>
                  <small>risk</small>
                </div>
              </div>
            </div>

            {/* Score bar */}
            <div className="score-bar-wrap">
              <div className="score-bar-track">
                <div
                  className="score-bar-fill"
                  style={{ width: `${result.score}%` }}
                />
              </div>
              <div className="score-bar-labels">
                <span>Safe</span>
                <span>Suspicious</span>
                <span>Dangerous</span>
              </div>
            </div>

            {/* Summary stats */}
            <div className="result-stats">
              <div className="stat-item">
                <AlertTriangle size={16} className="stat-icon triggered" />
                <span className="stat-num">{triggeredCount}</span>
                <span className="stat-label">flags triggered</span>
              </div>
              <div className="stat-item">
                <CheckCircle2 size={16} className="stat-icon passed" />
                <span className="stat-num">{passedCount}</span>
                <span className="stat-label">checks passed</span>
              </div>
              <div className="stat-item">
                <BarChart3 size={16} className="stat-icon neutral" />
                <span className="stat-num">{result.flags.length}</span>
                <span className="stat-label">total indicators</span>
              </div>
            </div>

            {/* Flag breakdown */}
            <div className="flags-section">
              <h3 className="flags-title">Indicator Breakdown</h3>
              <div className="flags-list">
                {result.flags.map((flag) => (
                  <FlagRow
                    key={flag.id}
                    flag={flag}
                    expanded={expandedFlag === flag.id}
                    onToggle={() => setExpandedFlag(expandedFlag === flag.id ? null : flag.id)}
                  />
                ))}
              </div>
            </div>

            <p className="result-disclaimer">
              <Info size={13} />
              This analysis uses heuristic rules and is for educational purposes. A "safe" result does not guarantee a site is legitimate — always verify independently.
            </p>
          </div>
        </section>
      )}

      {/* How it works */}
      <section className="how-section" id="how">
        <div className="section-inner">
          <h2 className="section-title">How PhishGuard Works</h2>
          <p className="section-subtitle">Every URL is checked against 15 proven phishing indicators — the same feature set used in academic phishing-detection research.</p>
          <div className="how-grid">
            <div className="how-card">
              <div className="how-icon"><Search size={24} /></div>
              <h3>Parse &amp; Inspect</h3>
              <p>The URL is decomposed into protocol, hostname, path, port, and query parameters — each part is examined for anomalies.</p>
            </div>
            <div className="how-card">
              <div className="how-icon"><Shield size={24} /></div>
              <h3>Score Indicators</h3>
              <p>15 heuristics score the URL by severity: high-risk signals (IP host, punycode, typosquatting) carry more weight than minor ones.</p>
            </div>
            <div className="how-card">
              <div className="how-icon"><BarChart3 size={24} /></div>
              <h3>Weighted Verdict</h3>
              <p>A combined risk score from 0–100 maps to a clear verdict: Safe, Suspicious, or Likely Phishing — with a full breakdown.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Indicators list */}
      <section className="indicators-section" id="indicators">
        <div className="section-inner">
          <h2 className="section-title">The 15 Indicators</h2>
          <p className="section-subtitle">Each indicator targets a specific technique documented in phishing research and real-world attacks.</p>
          <div className="indicators-grid">
            {INDICATOR_REFERENCE.map((ind, i) => (
              <div key={ind.name} className="indicator-card">
                <span className="indicator-num">{String(i + 1).padStart(2, "0")}</span>
                <h4>{ind.name}</h4>
                <p>{ind.desc}</p>
                <span className={`indicator-severity ${ind.sev}`}>{ind.sev}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* History */}
      {history.length > 0 && (
        <section className="history-section">
          <div className="section-inner">
            <h2 className="section-title">Recent Checks</h2>
            <div className="history-list">
              {history.map((h, i) => (
                <div key={i} className="history-item">
                  <div className="history-icon">
                    {h.verdict === "safe" && <ShieldCheck size={18} />}
                    {h.verdict === "suspicious" && <ShieldAlert size={18} />}
                    {h.verdict === "dangerous" && <ShieldAlert size={18} />}
                  </div>
                  <span className="history-url" title={h.url}>{h.url}</span>
                  <span className={`history-verdict ${h.verdict}`}>{verdictLabel(h.verdict)}</span>
                  <span className="history-score">{h.score}</span>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {/* Footer */}
      <footer className="footer">
        <div className="footer-inner">
          <div className="footer-brand">
            <Shield size={20} />
            <span>PhishGuard</span>
          </div>
          <p>Phishing URL detection tool — heuristic analysis for educational and defensive use. No URLs are sent to any server; all analysis runs in your browser.</p>
          <div className="footer-tags">
            <span><Lock size={12} /> 100% client-side</span>
            <span><Zap size={12} /> No data stored</span>
            <span><Scan size={12} /> 15 indicators</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

function FlagRow({ flag, expanded, onToggle }: { flag: PhishingFlag; expanded: boolean; onToggle: () => void }) {
  return (
    <div className={`flag-row ${flag.triggered ? "triggered" : "passed"} ${expanded ? "expanded" : ""}`}>
      <button className="flag-header" onClick={onToggle} aria-expanded={expanded}>
        <div className="flag-left">
          {flag.triggered ? <XCircle size={18} className="flag-icon triggered" /> : <CheckCircle2 size={18} className="flag-icon passed" />}
          <span className="flag-label">{flag.label}</span>
        </div>
        <div className="flag-right">
          {flag.triggered && <span className={`sev-badge ${flag.severity}`}>{flag.severity}</span>}
          {flag.value && <span className="flag-value">{flag.value}</span>}
          <ChevronDown size={16} className={`chev ${expanded ? "up" : ""}`} />
        </div>
      </button>
      {expanded && (
        <div className="flag-detail">
          <p>{flag.description}</p>
        </div>
      )}
    </div>
  );
}

const INDICATOR_REFERENCE = [
  { name: "IP as Hostname", desc: "Raw IP addresses instead of domain names often hide ownership.", sev: "high" as const },
  { name: "Excessive URL Length", desc: "URLs over 75 chars can hide redirects or encode payloads.", sev: "medium" as const },
  { name: "@ Symbol", desc: "Everything before @ is ignored by the browser — classic deception.", sev: "high" as const },
  { name: "Many Subdomains", desc: "4+ subdomain levels can bury the real domain in the hierarchy.", sev: "medium" as const },
  { name: "Hyphen Abuse", desc: "Multiple hyphens mimic brand names like secure-login-paypal.", sev: "medium" as const },
  { name: "Suspicious TLD", desc: ".zip, .xyz, .tk, .top and others are frequently abused.", sev: "medium" as const },
  { name: "No HTTPS", desc: "Unencrypted HTTP connections expose data and signal low legitimacy.", sev: "medium" as const },
  { name: "URL Shortener", desc: "Shortened links hide the true destination from the user.", sev: "low" as const },
  { name: "Non-Standard Port", desc: "Ports other than 80/443 can indicate unexpected services.", sev: "low" as const },
  { name: "Redirect Parameter", desc: "Open redirect params can bounce users to phishing pages.", sev: "medium" as const },
  { name: "Punycode Domain", desc: "Internationalized domains can impersonate brands via lookalikes.", sev: "high" as const },
  { name: "Typosquatting", desc: "Domains 1–2 characters from a trusted brand are a red flag.", sev: "high" as const },
  { name: "Special Characters", desc: "%, //, ~, ! in paths can obfuscate the real resource.", sev: "low" as const },
  { name: "Double Slash in Path", desc: "Extra slashes confuse parsers and hide destinations.", sev: "low" as const },
  { name: "Encoded Hostname", desc: "Percent-encoded chars in the hostname are abnormal and deceptive.", sev: "medium" as const },
];
