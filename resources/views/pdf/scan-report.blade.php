<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: Arial, sans-serif; background: #fff; color: #1a1a1a; font-size: 13px; }

  .header { background: #0a0a0a; color: #fff; padding: 28px 32px; }
  .header-top { display: flex; justify-content: space-between; align-items: flex-start; }
  .logo { font-size: 20px; font-weight: 900; letter-spacing: .08em; color: #fff; }
  .logo span { color: #FF6A1C; }
  .header-meta { text-align: right; font-size: 10px; color: #666; line-height: 1.6; }
  .report-title { font-size: 11px; color: #555; margin-top: 14px; letter-spacing: .12em; }

  .verdict-bar { padding: 20px 32px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
  .verdict-label { font-size: 22px; font-weight: 900; letter-spacing: .06em; }
  .verdict-safe { color: #00AA55; }
  .verdict-caution { color: #FFAD33; }
  .verdict-suspicious { color: #FF6A1C; }
  .verdict-malicious { color: #FF3B3B; }
  .score-box { text-align: center; border: 2px solid #eee; border-radius: 8px; padding: 12px 20px; }
  .score-num { font-size: 28px; font-weight: 900; color: #1a1a1a; }
  .score-label { font-size: 9px; color: #999; letter-spacing: .1em; margin-top: 2px; }

  .url-box { background: #f8f8f8; border-left: 3px solid #FF6A1C; margin: 0 32px; padding: 12px 16px; border-radius: 0 4px 4px 0; margin-top: 16px; margin-bottom: 8px; }
  .url-text { font-family: 'Courier New', monospace; font-size: 11px; color: #333; word-break: break-all; }
  .url-meta { font-size: 10px; color: #999; margin-top: 4px; }

  .section { padding: 20px 32px; border-bottom: 1px solid #f0f0f0; }
  .section-title { font-size: 9px; font-weight: 700; letter-spacing: .14em; color: #999; margin-bottom: 14px; }

  .checks-grid { display: table; width: 100%; border-collapse: separate; border-spacing: 10px; }
  .check-card { display: table-cell; width: 25%; vertical-align: top; border: 1px solid #eee; border-radius: 6px; padding: 12px; }
  .check-name { font-size: 9px; font-weight: 700; letter-spacing: .1em; color: #999; margin-bottom: 6px; }
  .check-verdict { font-size: 11px; font-weight: 700; margin-bottom: 4px; }
  .check-detail { font-size: 10px; color: #777; line-height: 1.4; }
  .status-safe { color: #00AA55; }
  .status-warn { color: #FFAD33; }
  .status-danger { color: #FF3B3B; }
  .status-error { color: #999; }

  .flag-row { display: flex; align-items: flex-start; padding: 7px 0; border-bottom: 1px solid #f5f5f5; }
  .flag-row:last-child { border-bottom: none; }
  .flag-dot { width: 7px; height: 7px; border-radius: 50%; margin-top: 3px; margin-right: 10px; flex-shrink: 0; }
  .flag-dot-pass { background: #00AA55; }
  .flag-dot-warn { background: #FFAD33; }
  .flag-dot-fail { background: #FF3B3B; }
  .flag-check { font-size: 10px; font-weight: 700; color: #333; width: 130px; flex-shrink: 0; }
  .flag-msg { font-size: 10px; color: #666; line-height: 1.4; }

  .brand-box { border: 1px solid #eee; border-radius: 6px; padding: 14px; }
  .brand-impersonating { border-color: #FF3B3B; background: #fff8f8; }
  .brand-safe-box { border-color: #00AA55; background: #f8fff8; }

  .footer { background: #0a0a0a; color: #555; padding: 16px 32px; margin-top: 24px; }
  .footer-inner { display: flex; justify-content: space-between; font-size: 9px; }

  .score-bar-bg { height: 5px; background: #eee; border-radius: 3px; overflow: hidden; margin-top: 8px; }
  .score-bar-fill { height: 100%; border-radius: 3px; }
</style>
</head>
<body>

{{-- HEADER --}}
<div class="header">
  <div class="header-top">
    <div>
      <div class="logo"><span>PHISH</span>GUARD PK</div>
      <div class="report-title">SECURITY SCAN REPORT</div>
    </div>
    <div class="header-meta">
      Report ID: #{{ $scan->id }}<br>
      Generated: {{ now()->format('d M Y, H:i') }}<br>
      Scanned: {{ \Carbon\Carbon::parse($scan->created_at)->format('d M Y, H:i') }}
    </div>
  </div>
</div>

{{-- VERDICT BAR --}}
@php
  $verdict = $scan->verdict;
  $score = $scan->risk_score;
  $scoreColor = $score >= 70 ? '#FF3B3B' : ($score >= 40 ? '#FF6A1C' : ($score >= 15 ? '#FFAD33' : '#00AA55'));
@endphp
<div class="verdict-bar">
  <div>
    <div style="font-size:10px;color:#999;letter-spacing:.1em;margin-bottom:6px;">FINAL VERDICT</div>
    <div class="verdict-label verdict-{{ $verdict }}">{{ strtoupper($verdict) }}</div>
    <div style="font-size:10px;color:#999;margin-top:4px;">
      @if($verdict === 'malicious') Do not open this URL. Report to FIA Cyber Crime Wing.
      @elseif($verdict === 'suspicious') Proceed with extreme caution. Verify through official channels.
      @elseif($verdict === 'caution') Some risk indicators detected. Double-check before clicking.
      @else No significant threats detected. Exercise normal caution.
      @endif
    </div>
  </div>
  <div class="score-box">
    <div class="score-num" style="color:{{ $scoreColor }}">{{ $score }}</div>
    <div class="score-label">RISK SCORE / 100</div>
    <div class="score-bar-bg" style="width:80px;margin:6px auto 0;">
      <div class="score-bar-fill" style="width:{{ $score }}%;background:{{ $scoreColor }};"></div>
    </div>
  </div>
</div>

{{-- URL INFO --}}
<div class="url-box">
  <div class="url-text">{{ $scan->url }}</div>
  <div class="url-meta">Domain: {{ $scan->domain }} &nbsp;|&nbsp; Source: {{ ucfirst($scan->virustotal_result['source'] ?? 'fresh') }} scan</div>
</div>

{{-- 4 CHECK CARDS --}}
<div class="section">
  <div class="section-title">ANALYSIS LAYERS</div>

  @php
    $vt     = $scan->virustotal_result ?? [];
    $gsb    = $scan->google_sb_result ?? [];
    $domain = $scan->domain_age_result ?? [];
    $brand  = $scan->brand_impersonation_result ?? [];
  @endphp

  <div class="checks-grid">
    {{-- VirusTotal --}}
    <div class="check-card">
      <div class="check-name">VIRUSTOTAL</div>
      @if(($vt['status'] ?? '') === 'error' || ($vt['status'] ?? '') === 'unavailable')
        <div class="check-verdict status-warning">UNAVAILABLE</div>
        <div class="check-detail">{{ $vt['message'] ?? 'VirusTotal is temporarily unavailable. Other checks still completed normally.' }}</div>
      @else
        <div class="check-verdict {{ ($vt['malicious'] ?? 0) > 0 ? 'status-danger' : 'status-safe' }}">
          {{ ($vt['malicious'] ?? 0) > 0 ? 'FLAGGED' : 'CLEAN' }}
        </div>
        <div class="check-detail">
          {{ $vt['malicious'] ?? 0 }} malicious · {{ $vt['suspicious'] ?? 0 }} suspicious<br>
          out of {{ $vt['total_engines'] ?? 0 }} engines
        </div>
      @endif
    </div>

    {{-- Google Safe Browsing --}}
    <div class="check-card">
      <div class="check-name">GOOGLE SAFE BROWSING</div>
      <div class="check-verdict {{ ($gsb['flagged'] ?? false) ? 'status-danger' : 'status-safe' }}">
        {{ ($gsb['flagged'] ?? false) ? 'THREAT FOUND' : 'CLEAN' }}
      </div>
      <div class="check-detail">{{ $gsb['summary'] ?? 'No data' }}</div>
    </div>

    {{-- Domain Age --}}
    <div class="check-card">
      <div class="check-name">DOMAIN AGE</div>
      @if(($domain['status'] ?? '') === 'success')
        <div class="check-verdict {{ ($domain['is_new'] ?? false) ? 'status-danger' : 'status-safe' }}">
          {{ ($domain['is_new'] ?? false) ? 'NEW DOMAIN' : 'ESTABLISHED' }}
        </div>
        <div class="check-detail">
          Age: {{ $domain['age_human'] ?? 'Unknown' }}<br>
          Registrar: {{ $domain['registrar'] ?? 'Unknown' }}
        </div>
      @else
        <div class="check-verdict status-error">UNKNOWN</div>
        <div class="check-detail">Registration date could not be determined.</div>
      @endif
    </div>

    {{-- Brand Impersonation --}}
    <div class="check-card">
      <div class="check-name">BRAND IMPERSONATION</div>
      @if($brand['is_impersonating'] ?? false)
        <div class="check-verdict status-danger">DETECTED</div>
        <div class="check-detail">
          Impersonating: {{ $brand['matched_brand'] ?? 'Unknown' }}<br>
          Method: {{ str_replace('_', ' ', $brand['technique'] ?? '') }}
        </div>
      @else
        <div class="check-verdict status-safe">NONE DETECTED</div>
        <div class="check-detail">{{ $brand['summary'] ?? 'No brand impersonation found.' }}</div>
      @endif
    </div>
  </div>
</div>

{{-- PATTERN FLAGS --}}
@if(!empty($scan->pattern_result['flags']))
<div class="section">
  <div class="section-title">URL PATTERN ANALYSIS</div>
  @foreach($scan->pattern_result['flags'] as $flag)
  <div class="flag-row">
    <div class="flag-dot flag-dot-{{ $flag['status'] === 'pass' ? 'pass' : ($flag['status'] === 'warn' ? 'warn' : 'fail') }}"></div>
    <div class="flag-check">{{ strtoupper($flag['check']) }}</div>
    <div class="flag-msg">{{ $flag['message'] }}</div>
  </div>
  @endforeach
</div>
@endif

{{-- FOOTER --}}
<div class="footer">
  <div class="footer-inner">
    <span>PhishGuard PK — Pakistan's Free Phishing Detection Service</span>
    <span>This report is for informational purposes only. phishguard.pk</span>
  </div>
</div>

</body>
</html>