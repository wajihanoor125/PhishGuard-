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
  const cio = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) { animateCounter(e.target); cio.unobserve(e.target); }
    });
  }, { threshold: .2 });
  document.querySelectorAll('.counter').forEach(el => cio.observe(el));
}

// ── SCANNER: INTERCEPT FORM ───────────────────────────────────────────────────
let scanProgressTimer = null;

document.addEventListener('DOMContentLoaded', () => {
  initReveal();
  renderDoc('overview', document.querySelector('.docs-nav'));

  const form = document.querySelector('#scanner form');
  if (form) form.addEventListener('submit', handleScan);
});

function startScanProgress() {
  const progress = document.getElementById('scanProgress');
  const bar = document.getElementById('scanProgressBar');
  const text = document.getElementById('scanProgressText');
  const caption = document.getElementById('scanProgressCaption');

  if (!progress || !bar || !text || !caption) return null;

  progress.classList.add('active');
  progress.style.display = 'block';
  bar.style.width = '0%';
  text.textContent = '0%';
  caption.textContent = 'Preparing scan…';

  clearInterval(scanProgressTimer);

  const stages = [
    { percent: 16, label: 'Preparing scan…' },
    { percent: 34, label: 'Checking URL structure…' },
    { percent: 58, label: 'Running security checks…' },
    { percent: 80, label: 'Combining threat signals…' },
    { percent: 94, label: 'Finalizing verdict…' }
  ];

  let index = 0;
  const tick = () => {
    const stage = stages[index];
    if (!stage) return;
    bar.style.width = `${stage.percent}%`;
    text.textContent = `${stage.percent}%`;
    caption.textContent = stage.label;
    index += 1;
  };

  tick();
  scanProgressTimer = setInterval(tick, 650);
  return scanProgressTimer;
}

function finishScanProgress() {
  const progress = document.getElementById('scanProgress');
  const bar = document.getElementById('scanProgressBar');
  const text = document.getElementById('scanProgressText');
  const caption = document.getElementById('scanProgressCaption');

  if (!progress || !bar || !text || !caption) return;

  clearInterval(scanProgressTimer);
  bar.style.width = '100%';
  text.textContent = '100%';
  caption.textContent = 'Results ready';
}

async function handleScan(e) {
  e.preventDefault();

  const url = document.getElementById('urlInput').value.trim();
  const resultsDiv = document.getElementById('scanResults');
  const layerProg = document.getElementById('layerProgress');
  const scanningInd = document.getElementById('scanningInd');
  const scanBeam = document.getElementById('scanBeam');
  const urlError = document.getElementById('urlError');

  if (!url) { urlError.textContent = 'Please enter a URL to scan.'; return; }

  // Reset state
  resultsDiv.innerHTML = '';
  urlError.textContent = '';

  // Show scanning UI
  scanningInd.style.display = 'flex';
  scanBeam.style.display = 'block';
  layerProg.style.display = 'block';
  startScanProgress();

  // Animate all 4 layer dots to "checking"
  for (let i = 0; i < 4; i++) {
    const dot = document.getElementById(`ld${i}`);
    const stat = document.getElementById(`ls${i}`);
    dot.style.background = '#FFAD33';
    dot.style.boxShadow = '0 0 8px #FFAD33';
    stat.textContent = 'CHECKING...';
    stat.style.color = '#FFAD33';
  }

  try {
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content;

    const response = await fetch('/api/url', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...(csrf ? { 'X-CSRF-TOKEN': csrf } : {})
      },
      body: JSON.stringify({ url })
    });

    const data = await response.json();

    if (!response.ok) {
      urlError.textContent = data.errors?.url?.[0] || 'Invalid URL. Please check and try again.';
      resetScanState();
      return;
    }

    finishScanProgress();

    // Update layer dots with real results
    updateLayerDots(data);

    // Brief pause so user sees the results, then render
    setTimeout(() => {
      scanningInd.style.display = 'none';
      scanBeam.style.display = 'none';
      renderResults(data, resultsDiv);
    }, 900);

  } catch (err) {
    urlError.textContent = 'Connection failed. Please try again.';
    resetScanState();
  }
}

function resetScanState() {
  clearInterval(scanProgressTimer);
  const progress = document.getElementById('scanProgress');
  const bar = document.getElementById('scanProgressBar');
  const text = document.getElementById('scanProgressText');
  const caption = document.getElementById('scanProgressCaption');

  if (progress) {
    progress.classList.remove('active');
    progress.style.display = 'none';
  }
  if (bar) bar.style.width = '0%';
  if (text) text.textContent = '0%';
  if (caption) caption.textContent = 'Preparing scan…';
  document.getElementById('scanningInd').style.display = 'none';
  document.getElementById('scanBeam').style.display = 'none';
  document.getElementById('layerProgress').style.display = 'none';
}

function updateLayerDots(data) {
  const layers = [
    data.virustotal_result,
    data.google_sb_result,
    data.domain_age_result,
    data.pattern_result
  ];

  layers.forEach((result, i) => {
    const dot = document.getElementById(`ld${i}`);
    const stat = document.getElementById(`ls${i}`);
    dot.style.animation = 'none';

    if (!result || result.status === 'error' || result.status === 'unavailable') {
      dot.style.background = '#FFAD33';
      dot.style.boxShadow = '0 0 8px #FFAD33';
      stat.textContent = 'UNAVAILABLE';
      stat.style.color = '#FFAD33';
    } else if (result.status === 'unknown') {
      dot.style.background = '#666';
      dot.style.boxShadow = 'none';
      stat.textContent = 'UNKNOWN';
      stat.style.color = '#666';
    } else if (result.verdict === 'malicious' || result.verdict === 'suspicious' || result.flagged || result.is_impersonating) {
      dot.style.background = '#FF6A1C';
      dot.style.boxShadow = '0 0 8px #FF6A1C';
      stat.textContent = 'THREAT FOUND';
      stat.style.color = '#FF6A1C';
    } else if (result.verdict === 'caution' || result.is_new) {
      dot.style.background = '#FFAD33';
      dot.style.boxShadow = '0 0 8px #FFAD33';
      stat.textContent = 'CAUTION';
      stat.style.color = '#FFAD33';
    } else {
      dot.style.background = '#00D084';
      dot.style.boxShadow = '0 0 8px #00D084';
      stat.textContent = 'CLEAN';
      stat.style.color = '#00D084';
    }
  });
}

// ── RESULTS RENDERER ──────────────────────────────────────────────────────────
function renderResults(data, container) {
  const vCfg = {
    malicious: { color: '#FF3B3B', bg: 'rgba(255,59,59,0.06)', border: 'rgba(255,59,59,0.2)', label: 'MALICIOUS' },
    suspicious: { color: '#FF6A1C', bg: 'rgba(255,106,28,0.06)', border: 'rgba(255,106,28,0.2)', label: 'SUSPICIOUS' },
    caution: { color: '#FFAD33', bg: 'rgba(255,173,51,0.06)', border: 'rgba(255,173,51,0.2)', label: 'CAUTION' },
    safe: { color: '#00D084', bg: 'rgba(0,208,132,0.06)', border: 'rgba(0,208,132,0.2)', label: 'SAFE' },
  };
  const v = vCfg[data.verdict] || vCfg.safe;
  const sColor = data.risk_score >= 70 ? '#FF3B3B' : data.risk_score >= 40 ? '#FF6A1C' : data.risk_score >= 15 ? '#FFAD33' : '#00D084';
  const scannedAt = new Date(data.scanned_at).toLocaleString('en-PK', { dateStyle: 'medium', timeStyle: 'short' });

  container.style.marginTop = '2rem';
  container.innerHTML = `

    <!-- ── VERDICT HERO ── -->
    <div style="background:${v.bg};border:1px solid ${v.border};border-radius:1rem;padding:1.75rem 2rem;margin-bottom:1.25rem;position:relative;overflow:hidden;">
      <div style="position:absolute;inset:0;background:radial-gradient(ellipse at top center,${v.color}06 0%,transparent 65%);pointer-events:none;"></div>

      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1.5rem;position:relative;">
        <!-- Left: verdict -->
        <div style="display:flex;align-items:center;gap:1rem;">
          <div style="width:52px;height:52px;flex-shrink:0;border-radius:50%;background:${v.bg};border:1px solid ${v.border};display:flex;align-items:center;justify-content:center;">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="${v.color}" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </div>
          <div>
            <div id="verdictLabel" style="font-family:'Orbitron',sans-serif;font-size:1.5rem;font-weight:900;color:${v.color};letter-spacing:.04em;">${v.label}</div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:.65rem;color:#555;margin-top:.2rem;">SCANNED · ${scannedAt} ${data.source === 'cache' ? '· <span style="color:#444">CACHED</span>' : ''}</div>
          </div>
        </div>
        <!-- Right: score -->
        <div style="text-align:center;min-width:100px;">
          <div id="riskScore" style="font-family:'Orbitron',sans-serif;font-size:2.4rem;font-weight:900;color:${sColor};line-height:1;">${data.risk_score}</div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:.6rem;color:#555;letter-spacing:.08em;">/100 RISK SCORE</div>
          <div style="margin-top:.5rem;height:3px;background:rgba(255,255,255,0.05);border-radius:2px;overflow:hidden;">
            <div style="height:100%;width:0;background:${sColor};border-radius:2px;transition:width 1.2s cubic-bezier(.4,0,.2,1);" id="riskBar"></div>
          </div>
        </div>
      </div>

      <!-- URL row -->
      <div style="margin-top:1.25rem;padding-top:1.25rem;border-top:1px solid rgba(255,255,255,0.05);font-family:'JetBrains Mono',monospace;font-size:.72rem;">
        <span style="color:#444;">URL ▸ </span>
        <span style="color:#777;word-break:break-all;">${escHtml(data.url)}</span>
      </div>
    </div>

    <!-- ── 4 CHECK CARDS ── -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.9rem;margin-bottom:1.25rem;">
      ${buildVtCard(data.virustotal_result)}
      ${buildGsbCard(data.google_sb_result)}
      ${buildDomainCard(data.domain_age_result)}
      ${buildBrandCard(data.brand_impersonation_result)}
    </div>

    <!-- ── PATTERN FLAGS ── -->
    ${buildPatternSection(data.pattern_result)}

    <!-- ── ACTION BAR ── -->
    <div style="display:flex;gap:.75rem;flex-wrap:wrap;margin-top:1.25rem;padding:1.25rem 1.5rem;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.05);border-radius:.75rem;align-items:center;justify-content:space-between;">
      <div style="font-family:'JetBrains Mono',monospace;font-size:.65rem;color:#444;">SCAN ID #${data.scan_id}</div>
      <div style="display:flex;gap:.75rem;flex-wrap:wrap;">
        <a href="/report/${data.scan_id}" target="_blank"
           style="display:inline-flex;align-items:center;gap:.5rem;background:#FF6A1C;color:#fff;font-family:'Orbitron',sans-serif;font-size:.65rem;font-weight:700;letter-spacing:.06em;padding:.6rem 1.25rem;border-radius:.4rem;text-decoration:none;cursor:pointer;border:none;">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          DOWNLOAD REPORT
        </a>
        <button onclick="copyShareLink('${data.scan_id}')"
                style="display:inline-flex;align-items:center;gap:.5rem;background:transparent;color:#FF6A1C;font-family:'Orbitron',sans-serif;font-size:.65rem;font-weight:700;letter-spacing:.06em;padding:.6rem 1.25rem;border-radius:.4rem;cursor:pointer;border:1px solid rgba(255,106,28,0.35);" id="shareBtnWrap">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
          COPY SHARE LINK
        </button>
      </div>
    </div>
  `;

  // Animate risk bar
  requestAnimationFrame(() => {
    setTimeout(() => {
      const bar = document.getElementById('riskBar');
      if (bar) bar.style.width = data.risk_score + '%';
    }, 100);
  });

  if (data.virustotal_result?.status === 'pending') {
    startVtPolling(data.scan_id);
  }

  container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ── VT POLLER ───────────────────────────────────────────────────────────────
function startVtPolling(scanId) {
  let attempts = 0;
  const maxPolls = 20;
  const interval = 4000;

  const poller = setInterval(async () => {
    attempts++;

    if (attempts > maxPolls) {
      clearInterval(poller);
      updateVtCard({ status: 'error', summary: 'VT analysis timed out' });
      return;
    }

    try {
      const res = await fetch(`/api/scan/${scanId}/vt-status`);
      const data = await res.json();

      if (data.vt_ready) {
        clearInterval(poller);
        updateVtCard(data.virustotal_result);
        updateScoreAndVerdict(data.risk_score, data.verdict);
      }
    } catch (err) {
      console.error('VT poll error:', err);
    }
  }, interval);
}

function updateVtCard(vt) {
  const card = document.getElementById('vt-card');
  if (card) {
    card.outerHTML = buildVtCard(vt);
  }
}

function updateScoreAndVerdict(score, verdict) {
  const scoreEl = document.getElementById('riskScore');
  const bar = document.getElementById('riskBar');
  const vEl = document.getElementById('verdictLabel');

  const colors = {
    malicious: '#FF3B3B',
    suspicious: '#FF6A1C',
    caution: '#FFAD33',
    safe: '#00D084',
  };

  const color = colors[verdict] || '#00D084';

  if (scoreEl) {
    scoreEl.textContent = score;
    scoreEl.style.color = color;
  }

  if (bar) {
    bar.style.width = score + '%';
    bar.style.background = color;
  }

  if (vEl) {
    vEl.textContent = (verdict || 'safe').toUpperCase();
    vEl.style.color = color;
  }
}

// ── CARD BUILDERS ─────────────────────────────────────────────────────────────

function buildVtCard(vt) {
  if (!vt || vt.status === 'error' || vt.status === 'unavailable') {
    const title = 'VirusTotal temporarily unavailable';
    const body = 'This layer could not be completed right now. The scan results below remain useful, and the report can still be reviewed.';
    return `
      <div id="vt-card" style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.07);border-radius:.75rem;padding:1.1rem 1.25rem;border-top:2px solid #FFAD33;min-height:150px;display:flex;flex-direction:column;justify-content:space-between;box-sizing:border-box;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:.6rem;letter-spacing:.1em;color:#444;margin-bottom:.7rem;">VIRUSTOTAL</div>
        <div style="display:flex;align-items:center;gap:.45rem;margin-bottom:.65rem;flex-wrap:wrap;">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#FFAD33" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span style="font-family:'Orbitron',sans-serif;font-size:.75rem;font-weight:700;color:#FFAD33;">UNAVAILABLE</span>
        </div>
        <div style="font-family:'Inter',sans-serif;font-size:.72rem;color:#666;line-height:1.5;overflow-wrap:anywhere;">
          <div style="font-weight:600;color:#777;margin-bottom:.3rem;">${escHtml(title)}</div>
          <div>${escHtml(body)}</div>
        </div>
      </div>`;
  }
  const flagged = (vt.malicious || 0) > 0;
  const color = flagged ? '#FF3B3B' : '#00D084';
  const label = flagged ? 'FLAGGED' : 'CLEAN';
  const icon = flagged
    ? `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
    : `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`;

  return `<div id="vt-card">${checkCard('VirusTotal', color, label, icon,
    `${vt.malicious || 0} malicious · ${vt.suspicious || 0} suspicious`,
    `${vt.total_engines || 0} engines checked`
  )}</div>`;
}

function buildGsbCard(gsb) {
  if (!gsb || gsb.status === 'error') {
    return checkCard('Google Safe Browsing', '#666', 'ERROR',
      `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#666" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
      'Check unavailable', ''
    );
  }
  const flagged = gsb.flagged;
  const color = flagged ? '#FF3B3B' : '#00D084';
  const label = flagged ? 'THREAT' : 'CLEAN';
  const icon = flagged
    ? `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>`
    : `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`;

  return checkCard('Google Safe Browsing', color, label, icon,
    gsb.summary || 'No data',
    flagged ? `${(gsb.threats || []).length} threat type(s) detected` : ''
  );
}

function buildDomainCard(domain) {
  if (!domain || domain.status === 'error') {
    return checkCard('Domain Age', '#666', 'ERROR',
      `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#666" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
      'Could not determine age', ''
    );
  }
  if (domain.status === 'unknown') {
    return checkCard('Domain Age', '#FFAD33', 'UNKNOWN',
      `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#FFAD33" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
      'Registration data unavailable',
      'Treat with caution'
    );
  }
  const isNew = domain.is_new;
  const color = isNew ? '#FF6A1C' : '#00D084';
  const label = isNew ? 'NEW DOMAIN' : 'ESTABLISHED';
  const icon = isNew
    ? `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>`
    : `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`;

  return checkCard('Domain Age', color, label, icon,
    `Age: ${domain.age_human || 'Unknown'}`,
    `Registrar: ${domain.registrar || 'Unknown'}`
  );
}

function buildBrandCard(brand) {
  if (!brand || brand.status === 'error') {
    return checkCard('Brand Impersonation', '#666', 'ERROR',
      `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#666" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>`,
      'Check unavailable', ''
    );
  }
  const impersonating = brand.is_impersonating;
  const color = impersonating ? '#FF3B3B' : '#00D084';
  const label = impersonating ? 'DETECTED' : 'NONE';
  const icon = impersonating
    ? `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
    : `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`;

  const detail1 = impersonating ? `Impersonating: ${brand.matched_brand}` : (brand.summary || 'No brand match found');
  const detail2 = impersonating ? `Method: ${(brand.technique || '').replace(/_/g, ' ')}` : '';

  return checkCard('Brand Impersonation', color, label, icon, detail1, detail2);
}

function checkCard(name, color, label, icon, line1, line2) {
  return `
    <div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.07);border-radius:.75rem;padding:1.1rem 1.25rem;border-top:2px solid ${color}20;">
      <div style="font-family:'JetBrains Mono',monospace;font-size:.6rem;letter-spacing:.1em;color:#444;margin-bottom:.7rem;">${escHtml(name).toUpperCase()}</div>
      <div style="display:flex;align-items:center;gap:.45rem;margin-bottom:.6rem;">
        ${icon}
        <span style="font-family:'Orbitron',sans-serif;font-size:.75rem;font-weight:700;color:${color};">${label}</span>
      </div>
      <div style="font-family:'Inter',sans-serif;font-size:.72rem;color:#666;line-height:1.5;">
        ${escHtml(line1)}${line2 ? `<br><span style="color:#444;">${escHtml(line2)}</span>` : ''}
      </div>
    </div>`;
}

function buildPatternSection(pattern) {
  if (!pattern || !pattern.flags || !pattern.flags.length) return '';

  const rows = pattern.flags.map(flag => {
    const dotColor = flag.status === 'pass' ? '#00D084' : flag.status === 'warn' ? '#FFAD33' : '#FF3B3B';
    const msgColor = flag.status === 'pass' ? '#555' : flag.status === 'warn' ? '#FFAD33' : '#FF6A1C';
    return `
      <div style="display:flex;align-items:flex-start;gap:.75rem;padding:.7rem 0;border-bottom:1px solid rgba(255,255,255,0.04);">
        <div style="width:7px;height:7px;flex-shrink:0;border-radius:50%;background:${dotColor};margin-top:5px;box-shadow:0 0 6px ${dotColor};"></div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:.65rem;color:#555;width:110px;flex-shrink:0;padding-top:2px;">${escHtml(flag.check).toUpperCase()}</div>
        <div style="font-family:'Inter',sans-serif;font-size:.75rem;color:${msgColor};line-height:1.5;">${escHtml(flag.message)}</div>
      </div>`;
  }).join('');

  return `
    <div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.07);border-radius:.75rem;padding:1.1rem 1.5rem;margin-bottom:.1rem;">
      <div style="font-family:'JetBrains Mono',monospace;font-size:.6rem;letter-spacing:.1em;color:#444;margin-bottom:.5rem;">URL PATTERN FLAGS · ${pattern.flag_count} checks · score +${pattern.risk_score}</div>
      ${rows}
    </div>`;
}

// ── SHARE LINK ────────────────────────────────────────────────────────────────
function copyShareLink(scanId) {
  const link = `${window.location.origin}/report/${scanId}`;
  navigator.clipboard.writeText(link).then(() => {
    const btn = document.getElementById('shareBtnWrap');
    if (btn) {
      const orig = btn.innerHTML;
      btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> LINK COPIED`;
      btn.style.color = '#00D084';
      btn.style.borderColor = 'rgba(0,208,132,0.35)';
      setTimeout(() => {
        btn.innerHTML = orig;
        btn.style.color = '#FF6A1C';
        btn.style.borderColor = 'rgba(255,106,28,0.35)';
      }, 2000);
    }
  });
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
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
  -d <span style="color:#FF8C42">'{"url":"https://suspect-site.com"}'</span></pre>`,

  layers: `
    <h2>ANALYSIS LAYERS</h2>
    <div class="doc-layer" style="background:rgba(255,106,28,.04);border:1px solid rgba(255,106,28,.12)">
      <div class="dl-head"><span class="dl-num" style="color:#FF6A1C">01</span><span class="dl-name" style="color:#FF6A1C">VirusTotal</span></div>
      <p class="dl-desc">Submits the URL to the VirusTotal API, aggregating results from 92+ antivirus engines.</p>
    </div>
    <div class="doc-layer" style="background:rgba(255,173,51,.04);border:1px solid rgba(255,173,51,.12)">
      <div class="dl-head"><span class="dl-num" style="color:#FFAD33">02</span><span class="dl-name" style="color:#FFAD33">Google Safe Browsing</span></div>
      <p class="dl-desc">Queries Google Safe Browsing API v4 for Malware, Social Engineering, and Unwanted Software.</p>
    </div>
    <div class="doc-layer" style="background:rgba(255,140,66,.04);border:1px solid rgba(255,140,66,.12)">
      <div class="dl-head"><span class="dl-num" style="color:#FF8C42">03</span><span class="dl-name" style="color:#FF8C42">Domain Age</span></div>
      <p class="dl-desc">Performs a WHOIS lookup to determine domain creation date. Newly registered domains receive elevated risk scores.</p>
    </div>
    <div class="doc-layer" style="background:rgba(255,173,51,.04);border:1px solid rgba(255,173,51,.12)">
      <div class="dl-head"><span class="dl-num" style="color:#FFAD33">04</span><span class="dl-name" style="color:#FFAD33">URL Pattern Analysis</span></div>
      <p class="dl-desc">Analyzes structural URL features: brand impersonation, subdomain depth, IP literals, suspicious keywords, and SSL absence.</p>
    </div>`,

  scoring: `
    <h2>RISK SCORING</h2>
    <p>The risk score (0–100) is a weighted combination of all four layer outputs.</p>
    <div class="score-row" style="background:rgba(0,208,132,.07);border:1px solid rgba(0,208,132,.25)">
      <span class="score-range" style="color:#00D084">0–14</span>
      <div><div class="score-label" style="color:#00D084">SAFE</div><div class="score-desc">No significant threats detected.</div></div>
    </div>
    <div class="score-row" style="background:rgba(255,173,51,.07);border:1px solid rgba(255,173,51,.25)">
      <span class="score-range" style="color:#FFAD33">15–39</span>
      <div><div class="score-label" style="color:#FFAD33">CAUTION</div><div class="score-desc">Some risk indicators. Verify before proceeding.</div></div>
    </div>
    <div class="score-row" style="background:rgba(255,106,28,.07);border:1px solid rgba(255,106,28,.25)">
      <span class="score-range" style="color:#FF6A1C">40–69</span>
      <div><div class="score-label" style="color:#FF6A1C">SUSPICIOUS</div><div class="score-desc">Multiple indicators. High risk.</div></div>
    </div>
    <div class="score-row" style="background:rgba(255,59,59,.07);border:1px solid rgba(255,59,59,.3)">
      <span class="score-range" style="color:#FF3B3B">70–100</span>
      <div><div class="score-label" style="color:#FF3B3B">MALICIOUS</div><div class="score-desc">Do not open. Report to FIA Cyber Crime Wing.</div></div>
    </div>`,

  api: `
    <h2>API REFERENCE</h2>
    <div class="api-box">
      <div class="api-header">
        <span class="method-badge">POST</span>
        <span style="font-family:var(--font-mono);font-size:.9rem">/api/url</span>
      </div>
      <div class="api-body">
        <p style="color:#555;font-size:.75rem;font-family:var(--font-mono);margin-bottom:.4rem">REQUEST BODY</p>
        <pre>{ <span style="color:#FF6A1C">"url"</span>: <span style="color:#FF8C42">"https://example.com"</span> }</pre>
        <p style="color:#555;font-size:.75rem;font-family:var(--font-mono);margin-bottom:.4rem">RESPONSE</p>
        <pre>{
  <span style="color:#FF6A1C">"verdict"</span>: <span style="color:#FF8C42">"safe"</span> | <span style="color:#FF8C42">"caution"</span> | <span style="color:#FF8C42">"suspicious"</span> | <span style="color:#FF8C42">"malicious"</span>,
  <span style="color:#FF6A1C">"risk_score"</span>: 0–100,
  <span style="color:#FF6A1C">"scan_id"</span>: integer,
  <span style="color:#FF6A1C">"share_token"</span>: string
}</pre>
      </div>
    </div>`
};

function showDoc(id, btn) {
  document.getElementById('docsContent').innerHTML = docContent[id] || '';
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