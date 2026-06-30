<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PhishGuard PK — Free URL Phishing Detector</title>
  <meta name="description" content="Detect phishing URLs instantly. Free 4-layer analysis. No signup required." />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700;800;900&family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="css/style.css" />
</head>
<body>

  <!-- ── NAVBAR ── -->
  <nav id="navbar">
    <div class="nav-inner">
      <button class="logo" onclick="showPage('home')">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span><span class="orange">PHISH</span>GUARD <span class="amber small">PK</span></span>
      </button>
      <div class="nav-links" id="navLinks">
        <button class="nav-link active" data-page="home"   onclick="showPage('home')">Home</button>
        <button class="nav-link"        data-page="about"  onclick="showPage('about')">About</button>
        <button class="nav-link"        data-page="docs"   onclick="showPage('docs')">Docs</button>
        <button class="nav-link"        data-page="contact"onclick="showPage('contact')">Contact</button>
        <button class="btn-primary nav-cta" onclick="showPage('home');scrollToScanner()">SCAN NOW</button>
      </div>
      <button class="menu-toggle" id="menuToggle" onclick="toggleMenu()">
        <span id="menuIcon">&#9776;</span>
      </button>
    </div>
    <div class="mobile-menu" id="mobileMenu">
      <button class="mobile-link" onclick="showPage('home');toggleMenu()">Home</button>
      <button class="mobile-link" onclick="showPage('about');toggleMenu()">About</button>
      <button class="mobile-link" onclick="showPage('docs');toggleMenu()">Docs</button>
      <button class="mobile-link" onclick="showPage('contact');toggleMenu()">Contact</button>
    </div>
  </nav>


@yield('user')



<!-- ==================== FOOTER ==================== -->
  <footer>
    <div class="footer-inner">
      <div class="footer-top">
        <div>
          <div class="footer-logo">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#FF6A1C" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <span><span class="orange">PHISH</span>GUARD <span class="amber" style="font-size:.7rem">PK</span></span>
          </div>
          <p style="color:#888;font-size:.8rem;line-height:1.6;max-width:220px;margin-top:.5rem">Pakistan's free, instant URL phishing detection service. Protecting one click at a time.</p>
        </div>
        <div class="footer-col">
          <p class="footer-col-title mono">Navigation</p>
          <button onclick="showPage('home')">Home</button>
          <button onclick="showPage('about')">About</button>
          <button onclick="showPage('docs')">Docs</button>
          <button onclick="showPage('contact')">Contact</button>
        </div>
        <div class="footer-col">
          <p class="footer-col-title mono">Resources</p>
          <button onclick="showPage('docs')">API Reference</button>
          <button onclick="showPage('contact')">Report Phishing</button>
        </div>
        <div class="footer-col">
          <p class="footer-col-title mono">Legal</p>
          <button onclick="showPage('about')">Privacy Policy</button>
          <button onclick="showPage('about')">Terms of Use</button>
        </div>
      </div>
      <div class="footer-bottom">
        <span class="mono">© 2024 PhishGuard PK. Free forever. No tracking.</span>
        <span class="mono">Built with ❤️ in Pakistan 🇵🇰</span>
      </div>
    </div>
  </footer>

  <script src="js/script.js"></script>
</body>
</html>