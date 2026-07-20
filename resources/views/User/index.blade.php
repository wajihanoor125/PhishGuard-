@extends('User.navbar')
@section('user')



  <!-- ── PAGES ── -->
  <main id="main">

    <!-- HOME -->
    <div id="page-home" class="page active">

      <!-- Hero -->
      <section class="hero">
        <div class="grid-bg"></div>
        <div class="hero-radial"></div>
        <div class="orb orb1"></div>
        <div class="orb orb2"></div>
        <div class="orb orb3"></div>

        <div class="hero-content reveal-hero">
          <div class="badge">
            <span class="badge-dot"></span>
            Pakistan's Free Phishing Defense
          </div>

          <h1 class="hero-title">
            <span class="white">DETECT</span> <span class="orange glow-orange">PHISHING</span><br>
            <span class="white">BEFORE IT</span> <span class="orange glow-orange">STRIKES</span>
          </h1>

          <p class="hero-sub">
            Paste any suspicious URL and get an instant verdict — powered by 4 simultaneous
            security layers. Free, instant, no signup required.
          </p>

          <!-- SCANNER -->
          <div class="scanner-wrap" id="scanner">
            <div class="scanner-box" id="scannerBox">
              <div class="scan-beam" id="scanBeam"></div>
              <div class="scanner-row">
                <svg class="lock-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>

{{-- SUBMITING URL --}}
<form method="POST" action="{{ route('urlscan') }}" style="display: flex; gap: 0.5rem; align-items: center; width: 100%;">
  @csrf
  <input id="urlInput" type="text" placeholder="https://suspicious-link.com" autocomplete="off" name="url"/>
  <button class="btn-primary scan-btn" style="white-space: nowrap; padding: .65rem 1.2rem; font-size: .78rem; border-radius: .4rem; display: inline-flex; align-items: center; gap: 0.4rem;">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    SCAN
  </button>
</form>

                {{-- FORM FININSH --}}
                <div class="scanning-ind" id="scanningInd">
                  <div class="orbit-ring"></div>
                  <span class="mono">SCANNING</span>
                </div>
              </div>
            </div>
            <p class="url-error mono" id="urlError"></p>

            <div class="scan-progress" id="scanProgress" aria-live="polite" aria-label="Scan progress">
              <div class="scan-progress-head">
                <span class="mono scan-progress-label">SCAN PROGRESS</span>
                <span class="mono scan-progress-text" id="scanProgressText">0%</span>
              </div>
              <div class="scan-progress-track">
                <div class="scan-progress-bar" id="scanProgressBar"></div>
              </div>
              <div class="mono scan-progress-caption" id="scanProgressCaption">Preparing scan…</div>
            </div>

            <!-- Layer progress -->
            <div class="layer-progress" id="layerProgress">
              <p class="mono layer-title">RUNNING 4-LAYER ANALYSIS...</p>
              <div class="layer-item" id="li0"><div class="l-dot" id="ld0"></div><span class="mono l-name">VirusTotal (92 engines)</span><span class="mono l-status" id="ls0"></span></div>
              <div class="layer-item" id="li1"><div class="l-dot" id="ld1"></div><span class="mono l-name">Google Safe Browsing</span><span class="mono l-status" id="ls1"></span></div>
              <div class="layer-item" id="li2"><div class="l-dot" id="ld2"></div><span class="mono l-name">Domain Age Verification</span><span class="mono l-status" id="ls2"></span></div>
              <div class="layer-item" id="li3"><div class="l-dot" id="ld3"></div><span class="mono l-name">URL Pattern Analysis</span><span class="mono l-status" id="ls3"></span></div>
            </div>

            <!-- Results -->
            <div id="scanResults"></div>
          </div>
        </div>

        <div class="scroll-hint">
          <span class="mono" style="font-size:.55rem;letter-spacing:.3em;color:#555;margin-top:80px">SCROLL TO EXPLORE</span>
          <div class="scroll-line"></div>
        </div>
      </section>

      <!-- Stats -->
      <section class="stats-section">
        <div class="container">
          <div class="stats-grid">
            <div class="stat-card card-hover reveal"><div class="stat-val mono orange counter" data-target="92" data-suffix="+">0+</div><div class="stat-label">Security Engines</div></div>
            <div class="stat-card card-hover reveal"><div class="stat-val mono orange counter" data-target="4" data-suffix=" Layers">0 Layers</div><div class="stat-label">Threat Analysis</div></div>
            <div class="stat-card card-hover reveal"><div class="stat-val mono orange counter" data-target="3" data-suffix="s">0s</div><div class="stat-label">Scan Speed</div></div>
            <div class="stat-card card-hover reveal"><div class="stat-val mono orange counter" data-target="100" data-suffix="%">0%</div><div class="stat-label">Free Forever</div></div>
          </div>
        </div>
      </section>

      <!-- How It Works -->
      <section class="how-section">
        <div class="container">
          <div class="section-header reveal">
            <p class="section-tag mono">METHODOLOGY</p>
            <h2>HOW IT <span class="orange">WORKS</span></h2>
          </div>
          <div class="how-grid">
            <div class="how-card card-hover reveal">
              <div class="how-icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              </div>
              <div><span class="mono how-num">01</span><h3>Paste the URL</h3><p>Copy any suspicious link from SMS, WhatsApp, or email and paste it into the scanner.</p></div>
            </div>
            <div class="how-card card-hover reveal">
              <div class="how-icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
              </div>
              <div><span class="mono how-num">02</span><h3>4-Layer Analysis</h3><p>VirusTotal, Google Safe Browsing, domain age, and URL pattern checks run simultaneously.</p></div>
            </div>
            <div class="how-card card-hover reveal">
              <div class="how-icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              </div>
              <div><span class="mono how-num">03</span><h3>Risk Score</h3><p>A weighted score 0–100 combines all layer results into a unified threat index.</p></div>
            </div>
            <div class="how-card card-hover reveal">
              <div class="how-icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              </div>
              <div><span class="mono how-num">04</span><h3>Clear Verdict</h3><p>Safe, Suspicious, or Malicious with a plain-English explanation. No jargon, no confusion.</p></div>
            </div>
          </div>
        </div>
      </section>

      <!-- Features -->
      <section class="feat-section">
        <div class="container">
          <div class="section-header reveal">
            <p class="section-tag mono">CAPABILITIES</p>
            <h2>BUILT TO <span class="amber">PROTECT</span></h2>
          </div>
          <div class="feat-grid">
            <div class="feat-card card-hover reveal">
              <div class="feat-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4.03 3-9 3S3 13.66 3 12"/><path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/></svg></div>
              <h3>VirusTotal Integration</h3><p>Cross-referenced against 92+ global antivirus and security engines in real-time.</p>
            </div>
            <div class="feat-card card-hover reveal">
              <div class="feat-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></div>
              <h3>Google Safe Browsing</h3><p>Checks Google's continuously updated list of active phishing and malware sites.</p>
            </div>
            <div class="feat-card card-hover reveal">
              <div class="feat-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div>
              <h3>Domain Age Analysis</h3><p>Newly registered domains are a red flag — we check how old your target domain is.</p>
            </div>
            <div class="feat-card card-hover reveal">
              <div class="feat-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></div>
              <h3>Pattern Recognition</h3><p>Detects brand impersonation, IP-based URLs, suspicious keywords, and missing SSL.</p>
            </div>
            <div class="feat-card card-hover reveal">
              <div class="feat-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg></div>
              <h3>Instant Results</h3><p>All four layers run simultaneously. Get your verdict in under 3 seconds.</p>
            </div>
            <div class="feat-card card-hover reveal">
              <div class="feat-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
              <h3>100% Free Forever</h3><p>No signup, no tracking, no monetization. Built for the Pakistani internet user.</p>
            </div>
          </div>
        </div>
      </section>

      <!-- CTA -->
      <section class="cta-section">
        <div class="container">
          <div class="cta-card reveal">
            <div class="grid-bg"></div>
            <div class="cta-inner">
              <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2" class="cta-shield"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              <h2>STAY SAFE IN <span class="orange">PAKISTAN</span></h2>
              <p>Every day, Pakistanis lose money and data to phishing attacks. One free scan could save everything.</p>
              <div class="cta-btns">
                <button class="btn-primary" onclick="scrollToScanner()">SCAN A URL NOW</button>
                <button class="btn-outline" onclick="showPage('docs')">READ THE DOCS</button>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div><!-- /page-home -->

    <!-- ABOUT -->
    <div id="page-about" class="page">
      <section class="inner-page">
        <div class="container">
          <div class="page-header">
            <p class="section-tag mono">WHO WE ARE</p>
            <h1>ABOUT <span class="orange">PHISHGUARD</span></h1>
            <div class="header-line"></div>
          </div>
          <div class="about-grid">
            <div class="about-card card-hover reveal">
              <div class="about-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
              <h3>OUR MISSION</h3>
              <p>Pakistanis lose millions annually to phishing attacks. Banks, government services, and popular apps are impersonated daily via SMS, WhatsApp, and email. PhishGuard PK exists to put military-grade URL analysis in every Pakistani's pocket — for free, forever.</p>
            </div>
            <div class="about-card card-hover reveal">
              <div class="about-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></div>
              <h3>THE PROBLEM</h3>
              <p>In 2023, Pakistan ranked among the top 10 most phishing-targeted nations. Most victims click without checking. Existing tools are paid, require signups, return technical jargon, or are blocked by ISPs. We built the simplest possible solution.</p>
            </div>
            <div class="about-card card-hover reveal">
              <div class="about-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg></div>
              <h3>THE TECHNOLOGY</h3>
              <p>Four independent layers run in parallel: VirusTotal's 92+ engine collective, Google's real-time Safe Browsing database, WHOIS domain age verification, and a custom URL pattern classifier trained on 500,000+ Pakistani phishing samples.</p>
            </div>
            <div class="about-card card-hover reveal">
              <div class="about-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
              <h3>PRIVACY FIRST</h3>
              <p>We do not log URLs you scan, store any personal data, or sell information to third parties. Scans are ephemeral — nothing is retained after your results load. Your safety is the entire point.</p>
            </div>
          </div>
          <div class="team-wrap">
            <p class="section-tag mono" style="margin-bottom:1.5rem">THE TEAM</p>
            <div class="team-grid">
              <div class="team-card card-hover reveal"><div class="avatar">SM</div><h4>Samar Minallah</h4><p class="orange mono" style="font-size:.7rem">Founder &amp; Web Developer</p><p class="muted" style="font-size:.8rem;margin-top:.3rem">1 year in web development</p></div>
              <div class="team-card card-hover reveal"><div class="avatar">WN</div><h4>Wajiha Noor</h4><p class="orange mono" style="font-size:.7rem">Frontend Engineer</p><p class="muted" style="font-size:.8rem;margin-top:.3rem">1 year in web development</p></div>
             
            </div>
          </div>
        </div>
      </section>
    </div><!-- /page-about -->

    <!-- DOCS -->
    <div id="page-docs" class="page">
      <section class="inner-page">
        <div class="container">
          <div class="page-header">
            <p class="section-tag mono">DOCUMENTATION</p>
            <h1>TECHNICAL <span class="orange">DOCS</span></h1>
            <div class="header-line"></div>
          </div>
          <div class="docs-layout">
            <div class="docs-sidebar">
              <button class="docs-nav active" onclick="showDoc('overview',this)">Overview</button>
              <button class="docs-nav" onclick="showDoc('quickstart',this)">Quick Start</button>
              <button class="docs-nav" onclick="showDoc('layers',this)">Analysis Layers</button>
              <button class="docs-nav" onclick="showDoc('scoring',this)">Risk Scoring</button>
              <button class="docs-nav" onclick="showDoc('api',this)">API Reference</button>
            </div>
            <div class="docs-content" id="docsContent"></div>
          </div>
        </div>
      </section>
    </div><!-- /page-docs -->

    <!-- CONTACT -->
    <div id="page-contact" class="page">
      <section class="inner-page">
        <div class="container">
          <div class="page-header">
            <p class="section-tag mono">GET IN TOUCH</p>
            <h1>CONTACT <span class="orange">US</span></h1>
            <div class="header-line"></div>
          </div>
          <div class="contact-grid">
            <div class="contact-info reveal">
              <p style="color:#888;line-height:1.75;margin-bottom:1.5rem">Have questions, want to report a false positive, need API access, or want to collaborate? Reach us through any of the channels below.</p>
              <div class="contact-items">
                <div class="contact-item card-hover">
                  <div class="c-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></div>
                  <div><span class="mono" style="font-size:.65rem;color:#555">Email</span><p>security@phishguard.pk</p></div>
                </div>
                <div class="contact-item card-hover">
                  <div class="c-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.69 13.5 19.79 19.79 0 0 1 1.61 4.87C1.6 3.84 2.38 3 3.4 3h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L7.91 10.5a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg></div>
                  <div><span class="mono" style="font-size:.65rem;color:#555">Helpline</span><p>+92 300 PHISHPK</p></div>
                </div>
                <div class="contact-item card-hover">
                  <div class="c-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg></div>
                  <div><span class="mono" style="font-size:.65rem;color:#555">Location</span><p>Islamabad, Pakistan</p></div>
                </div>
              </div>
            </div>
            <div class="contact-form-wrap reveal" id="contactFormWrap">
              <form class="contact-form" onsubmit="submitForm(event)">
                <div class="form-group"><label class="mono form-label">FULL NAME</label><input type="text" placeholder="Muhammad Ali" required /></div>
                <div class="form-group"><label class="mono form-label">EMAIL ADDRESS</label><input type="email" placeholder="you@example.com" required /></div>
                <div class="form-group"><label class="mono form-label">SUBJECT</label><input type="text" placeholder="False positive report" required /></div>
                <div class="form-group"><label class="mono form-label">MESSAGE</label><textarea rows="4" placeholder="Describe your query..." required></textarea></div>
                <button type="submit" class="btn-primary submit-btn">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
                  SEND MESSAGE
                </button>
              </form>
            </div>
          </div>
        </div>
      </section>
    </div><!-- /page-contact -->

  </main>

@endsection
