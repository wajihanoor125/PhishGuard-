/* ── PhishGuard PK — script.js ── */

// ── PAGE ROUTING ──────────────────────────────────────────────────────────────
function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  document.querySelectorAll('.nav-link').forEach(l => {
    l.classList.toggle('active', l.dataset.page === id);
  });
  window.scrollTo({ top: 0, behavior: 'smooth' });
  if (id === 'docs') renderDoc('overview', document.querySelector('.docs-nav'));
  initReveal();
}

function scrollToScanner() {
  document.getElementById('scanner').scrollIntoView({ behavior: 'smooth' });
}

// ── MOBILE MENU ───────────────────────────────────────────────────────────────
function toggleMenu() {
  const m = document.getElementById('mobileMenu');
  const icon = document.getElementById('menuIcon');
  const open = m.classList.toggle('open');
  icon.innerHTML = open ? '&#10005;' : '&#9776;';
}

// ── NAVBAR SCROLL ─────────────────────────────────────────────────────────────
window.addEventListener('scroll', () => {
  document.getElementById('navbar').classList.toggle('scrolled', window.scrollY > 20);
});

// ── ANIMATED COUNTERS ─────────────────────────────────────────────────────────
function animateCounter(el) {
  const target = parseInt(el.dataset.target);
  const suffix = el.dataset.suffix || '';
  const duration = 1800;
  const steps = 60;
  const inc = target / steps;
  let current = 0;
  const timer = setInterval(() => {
    current += inc;
    if (current >= target) { el.textContent = target + suffix; clearInterval(timer); }
    else el.textContent = Math.floor(current) + suffix;
  }, duration / steps);
}

// ── SCROLL REVEAL + COUNTERS ──────────────────────────────────────────────────
function initReveal() {
  const io = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        e.target.classList.add('visible');
        const counters = e.target.querySelectorAll('.counter');
        counters.forEach(animateCounter);
        io.unobserve(e.target);
      }
    });
  }, { threshold: .12 });

  document.querySelectorAll('.reveal').forEach(el => io.observe(el));

  // Also observe stat cards for counters (since they're inside reveals)
  const cio = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) { animateCounter(e.target); cio.unobserve(e.target); }
    });
  }, { threshold: .2 });
  document.querySelectorAll('.counter').forEach(el => cio.observe(el));
}

// ── DOCS ──────────────────────────────────────────────────────────────────────
const docContent = {
  overview: `
    <h2>OVERVIEW</h2>
    <p>PhishGuard PK is a free, open-source URL phishing detection service built for the Pakistani internet ecosystem. It combines four independent threat intelligence layers into a single, human-readable verdict.</p>
    <div class="docs-meta-grid">
      <div class="docs-meta-item"><div class="docs-meta-val">99.9%</div><div class="docs-meta-lbl">Uptime</div></div>
      <div class="docs-meta-item"><div class="docs-meta-val">&lt; 3s</div><div class="docs-meta-lbl">Avg. Latency</div></div>
      <div class="docs-meta-item"><div class="docs-meta-val">100/hr</div><div class="docs-meta-lbl">Rate Limit</div></div>
    </div>
    <p style="color:#555;font-size:.8rem;font-family:var(--font-mono)">BASE ENDPOINT</p>
    <pre>https://api.phishguard.pk/v1/scan</pre>`,

  quickstart: `
    <h2>QUICK START</h2>
    <p>Send a POST request with the URL you want to analyze:</p>
    <p style="color:#555;font-size:.75rem;font-family:var(--font-mono);margin-bottom:.35rem"># cURL</p>
    <pre><span style="color:#FFAD33">curl</span> -X POST https://api.phishguard.pk/v1/scan \\
  -H <span style="color:#FF8C42">"Content-Type: application/json"</span> \\
  -d <span style="color:#FF8C42">'{"url":"https://suspect-site.com"}'</span></pre>
    <p style="color:#555;font-size:.75rem;font-family:var(--font-mono);margin-bottom:.35rem"># Python</p>
    <pre><span style="color:#FFAD33">import</span> requests

res = requests.<span style="color:#FF6A1C">post</span>(
    <span style="color:#FF8C42">"https://api.phishguard.pk/v1/scan"</span>,
    json=<span style="color:#FF8C42">{"url": "https://suspect.com"}</span>
)
<span style="color:#FFAD33">print</span>(res.json())</pre>`,

  layers: `
    <h2>ANALYSIS LAYERS</h2>
    <div class="doc-layer" style="background:rgba(255,106,28,.04);border:1px solid rgba(255,106,28,.12)">
      <div class="dl-head"><span class="dl-num" style="color:#FF6A1C">01</span><span class="dl-name" style="color:#FF6A1C">VirusTotal</span></div>
      <p class="dl-desc">Submits the URL to the VirusTotal API, aggregating results from 92+ antivirus engines. A consensus score derives from the ratio of flagging engines.</p>
      <div class="dl-code"><span style="color:#FF6A1C">engines_total</span>: 92 &nbsp;|&nbsp; <span style="color:#FF6A1C">engines_flagged</span>: 0-92 &nbsp;|&nbsp; <span style="color:#FF6A1C">last_analysis</span>: ISO 8601</div>
    </div>
    <div class="doc-layer" style="background:rgba(255,173,51,.04);border:1px solid rgba(255,173,51,.12)">
      <div class="dl-head"><span class="dl-num" style="color:#FFAD33">02</span><span class="dl-name" style="color:#FFAD33">Google Safe Browsing</span></div>
      <p class="dl-desc">Queries the Google Safe Browsing Lookup API v4 for Malware, Social Engineering, Unwanted Software, and Potentially Harmful Applications in real-time.</p>
      <div class="dl-code"><span style="color:#FFAD33">threat_types</span>: MALWARE | SOCIAL_ENGINEERING | UNWANTED_SOFTWARE &nbsp;|&nbsp; <span style="color:#FFAD33">match</span>: boolean</div>
    </div>
    <div class="doc-layer" style="background:rgba(255,140,66,.04);border:1px solid rgba(255,140,66,.12)">
      <div class="dl-head"><span class="dl-num" style="color:#FF8C42">03</span><span class="dl-name" style="color:#FF8C42">Domain Age</span></div>
      <p class="dl-desc">Performs a WHOIS lookup to determine domain creation date. Domains registered within 30 days receive elevated risk scores — phishing infrastructure is typically disposable.</p>
      <div class="dl-code"><span style="color:#FF8C42">created_date</span>: ISO 8601 &nbsp;|&nbsp; <span style="color:#FF8C42">age_days</span>: integer &nbsp;|&nbsp; <span style="color:#FF8C42">registrar</span>: string</div>
    </div>
    <div class="doc-layer" style="background:rgba(255,173,51,.04);border:1px solid rgba(255,173,51,.12)">
      <div class="dl-head"><span class="dl-num" style="color:#FFAD33">04</span><span class="dl-name" style="color:#FFAD33">URL Pattern Analysis</span></div>
      <p class="dl-desc">A lightweight ML classifier analyzes structural URL features: brand keyword presence, subdomain depth, hyphen frequency, IP literals, TLD risk, and SSL absence.</p>
      <div class="dl-code"><span style="color:#FFAD33">brand_impersonation</span>: boolean &nbsp;|&nbsp; <span style="color:#FFAD33">ip_based</span>: boolean &nbsp;|&nbsp; <span style="color:#FFAD33">ssl_present</span>: boolean</div>
    </div>`,

  scoring: `
    <h2>RISK SCORING</h2>
    <p>The risk score (0–100) is a weighted combination of all four layer outputs. Higher scores indicate greater threat likelihood.</p>
    <div class="score-row" style="background:rgba(255,173,51,.07);border:1px solid rgba(255,173,51,.25)">
      <span class="score-range" style="color:#FFAD33">0–24</span>
      <div><div class="score-label" style="color:#FFAD33">SAFE</div><div class="score-desc">No significant threats detected. Safe to visit with normal caution.</div></div>
    </div>
    <div class="score-row" style="background:rgba(255,140,66,.07);border:1px solid rgba(255,140,66,.25)">
      <span class="score-range" style="color:#FF8C42">25–59</span>
      <div><div class="score-label" style="color:#FF8C42">SUSPICIOUS</div><div class="score-desc">Some risk indicators present. Verify through official channels before proceeding.</div></div>
    </div>
    <div class="score-row" style="background:rgba(255,106,28,.07);border:1px solid rgba(255,106,28,.3)">
      <span class="score-range" style="color:#FF6A1C">60–100</span>
      <div><div class="score-label" style="color:#FF6A1C">MALICIOUS</div><div class="score-desc">High confidence threat. Do not visit. Report to FIA Cyber Crime Wing.</div></div>
    </div>
    <p style="margin-top:1.25rem;margin-bottom:.75rem">Layer weight distribution:</p>
    <div class="weight-row"><span class="wt-name">VirusTotal</span><div class="wt-bar-bg"><div class="wt-bar" style="width:35%"></div></div><span class="wt-pct">35%</span></div>
    <div class="weight-row"><span class="wt-name">Google Safe Browsing</span><div class="wt-bar-bg"><div class="wt-bar" style="width:30%"></div></div><span class="wt-pct">30%</span></div>
    <div class="weight-row"><span class="wt-name">Domain Age</span><div class="wt-bar-bg"><div class="wt-bar" style="width:20%"></div></div><span class="wt-pct">20%</span></div>
    <div class="weight-row"><span class="wt-name">URL Pattern</span><div class="wt-bar-bg"><div class="wt-bar" style="width:15%"></div></div><span class="wt-pct">15%</span></div>`,

  api: `
    <h2>API REFERENCE</h2>
    <div class="api-box">
      <div class="api-header">
        <span class="method-badge">POST</span>
        <span style="font-family:var(--font-mono);font-size:.9rem">/v1/scan</span>
      </div>
      <div class="api-body">
        <p style="color:#555;font-size:.75rem;font-family:var(--font-mono);margin-bottom:.4rem">REQUEST BODY</p>
        <pre>{
  <span style="color:#FF6A1C">"url"</span>: <span style="color:#FF8C42">"https://example.com"</span>,  // required
  <span style="color:#FF6A1C">"layers"</span>: <span style="color:#FF8C42">["all"]</span>              // optional
}</pre>
        <p style="color:#555;font-size:.75rem;font-family:var(--font-mono);margin-bottom:.4rem">RESPONSE</p>
        <pre>{
  <span style="color:#FF6A1C">"verdict"</span>: <span style="color:#FF8C42">"safe"</span> | <span style="color:#FF8C42">"suspicious"</span> | <span style="color:#FF8C42">"malicious"</span>,
  <span style="color:#FF6A1C">"score"</span>: 0-100,
  <span style="color:#FF6A1C">"layers"</span>: {
    <span style="color:#FFAD33">"virustotal"</span>:   { <span style="color:#FF6A1C">"engines_flagged"</span>: 0, <span style="color:#FF6A1C">"score"</span>: 5 },
    <span style="color:#FFAD33">"safebrowsing"</span>: { <span style="color:#FF6A1C">"match"</span>: false, <span style="color:#FF6A1C">"score"</span>: 2 },
    <span style="color:#FFAD33">"domain_age"</span>:   { <span style="color:#FF6A1C">"age_days"</span>: 1825, <span style="color:#FF6A1C">"score"</span>: 10 },
    <span style="color:#FFAD33">"url_pattern"</span>:  { <span style="color:#FF6A1C">"ip_based"</span>: false, <span style="color:#FF6A1C">"score"</span>: 8 }
  },
  <span style="color:#FF6A1C">"scan_id"</span>: <span style="color:#FF8C42">"uuid"</span>,
  <span style="color:#FF6A1C">"scanned_at"</span>: <span style="color:#FF8C42">"2024-01-15T10:30:00Z"</span>
}</pre>
      </div>
    </div>
    <div class="rate-limit-box">
      <div class="rl-title">⚠ RATE LIMITING</div>
      <p style="font-size:.85rem;color:#888">Free tier: 100 requests/hour per IP. For higher limits, contact us for an API key. Response headers include <code style="font-family:var(--font-mono);color:#FF6A1C">X-RateLimit-Remaining</code> and <code style="font-family:var(--font-mono);color:#FF6A1C">X-RateLimit-Reset</code>.</p>
    </div>`
};

function showDoc(id, btn) {
  document.getElementById('docsContent').innerHTML = docContent[id];
  document.getElementById('docsContent').style.animation = 'none';
  requestAnimationFrame(() => { document.getElementById('docsContent').style.animation = ''; });
  document.querySelectorAll('.docs-nav').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
}

function renderDoc(id, btn) {
  showDoc(id, btn || document.querySelector('.docs-nav'));
}

// ── CONTACT FORM ──────────────────────────────────────────────────────────────
function submitForm(e) {
  e.preventDefault();
  const wrap = document.getElementById('contactFormWrap');
  wrap.innerHTML = `
    <div class="success-msg active">
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#FFAD33" stroke-width="2" style="filter:drop-shadow(0 0 10px rgba(255,173,51,.5))">
        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
      </svg>
      <h3>MESSAGE SENT</h3>
      <p>We will respond within 24 hours. Stay safe online.</p>
    </div>`;
}

// ── INIT ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initReveal();
  renderDoc('overview', document.querySelector('.docs-nav'));
});