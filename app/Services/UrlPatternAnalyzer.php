<?php

namespace App\Services;

class UrlPatternAnalyzer
{
    private string $url;
    private string $scheme;
    private string $host;
    private string $path;
    private array  $flags = [];
    private int    $score = 0;

    public function analyze(string $url): array
    {
        $this->url    = $url;
        $this->scheme = strtolower(parse_url($url, PHP_URL_SCHEME) ?? '');
        $this->host   = strtolower(parse_url($url, PHP_URL_HOST)   ?? '');
        $this->path   = strtolower(parse_url($url, PHP_URL_PATH)   ?? '');

        $this->checkHttps();
        $this->checkUrlLength();
        $this->checkSuspiciousKeywords();
        $this->checkIpAddress();
        $this->checkSubdomains();

        return [
            'flags'       => $this->flags,
            'flag_count'  => count($this->flags),
            'risk_score'  => min($this->score, 40), // max 40 points from pattern check
        ];
    }

    // ─── Check 1: HTTPS ───────────────────────────────────────────────

    private function checkHttps(): void
    {
        if ($this->scheme !== 'https') {
            $this->flags[] = [
                'check'    => 'HTTPS',
                'status'   => 'fail',
                'message'  => 'Connection is not encrypted (HTTP instead of HTTPS)',
                'severity' => 'medium',
            ];
            $this->score += 10;
        } else {
            $this->flags[] = [
                'check'    => 'HTTPS',
                'status'   => 'pass',
                'message'  => 'Connection is encrypted (HTTPS)',
                'severity' => 'none',
            ];
        }
    }

    // ─── Check 2: URL Length ──────────────────────────────────────────

    private function checkUrlLength(): void
    {
        $length = strlen($this->url);

        if ($length > 200) {
            $this->flags[] = [
                'check'    => 'URL Length',
                'status'   => 'fail',
                'message'  => "URL is {$length} characters long — extremely suspicious",
                'severity' => 'high',
            ];
            $this->score += 15;

        } elseif ($length > 100) {
            $this->flags[] = [
                'check'    => 'URL Length',
                'status'   => 'warn',
                'message'  => "URL is {$length} characters — longer than normal",
                'severity' => 'low',
            ];
            $this->score += 5;

        } else {
            $this->flags[] = [
                'check'    => 'URL Length',
                'status'   => 'pass',
                'message'  => "URL length is normal ({$length} characters)",
                'severity' => 'none',
            ];
        }
    }

    // ─── Check 3: Suspicious Keywords ────────────────────────────────

    private function checkSuspiciousKeywords(): void
    {
        $keywords = [
            // Account & login
            'login', 'signin', 'sign-in', 'log-in', 'logon',

            // Verification
            'verify', 'verification', 'validate', 'confirm', 'authenticate',

            // Account actions
            'account', 'update', 'secure', 'security', 'password', 'reset',

            // Financial
            'banking', 'payment', 'wallet', 'transfer', 'transaction',

            // Pakistani context
            'easypaisa', 'jazzcash', 'nayapay', 'sadapay', 'nadra', 'fbr',
        ];

        $fullUrl  = strtolower($this->url);
        $matched  = [];

        foreach ($keywords as $keyword) {
            if (str_contains($fullUrl, $keyword)) {
                $matched[] = $keyword;
            }
        }

        if (count($matched) >= 3) {
            $this->flags[] = [
                'check'    => 'Suspicious Keywords',
                'status'   => 'fail',
                'message'  => 'Multiple suspicious keywords found: ' . implode(', ', $matched),
                'severity' => 'high',
            ];
            $this->score += 20;

        } elseif (count($matched) > 0) {
            $this->flags[] = [
                'check'    => 'Suspicious Keywords',
                'status'   => 'warn',
                'message'  => 'Suspicious keyword found in URL: ' . implode(', ', $matched),
                'severity' => 'medium',
            ];
            $this->score += 10;

        } else {
            $this->flags[] = [
                'check'    => 'Suspicious Keywords',
                'status'   => 'pass',
                'message'  => 'No suspicious keywords found',
                'severity' => 'none',
            ];
        }
    }

    // ─── Check 4: IP Address in URL ──────────────────────────────────

    private function checkIpAddress(): void
    {
        // Remove port if present e.g. 192.168.1.1:8080
        $hostWithoutPort = explode(':', $this->host)[0];

        if (filter_var($hostWithoutPort, FILTER_VALIDATE_IP)) {
            $this->flags[] = [
                'check'    => 'IP Address',
                'status'   => 'fail',
                'message'  => "URL uses a raw IP address ({$hostWithoutPort}) instead of a domain name — strong phishing indicator",
                'severity' => 'high',
            ];
            $this->score += 25;
        } else {
            $this->flags[] = [
                'check'    => 'IP Address',
                'status'   => 'pass',
                'message'  => 'URL uses a proper domain name, not an IP address',
                'severity' => 'none',
            ];
        }
    }

    // ─── Check 5: Subdomains ─────────────────────────────────────────

    private function checkSubdomains(): void
    {
        // Remove www. before counting
        $cleanHost = preg_replace('/^www\./', '', $this->host);
        $parts     = explode('.', $cleanHost);
        $count     = count($parts);

        // e.g. secure.hbl.login.verify.com → 4 parts = 3 subdomains
        if ($count > 4) {
            $this->flags[] = [
                'check'    => 'Subdomains',
                'status'   => 'fail',
                'message'  => "Excessive subdomains detected ({$this->host}) — common in phishing to disguise the real domain",
                'severity' => 'high',
            ];
            $this->score += 20;

        } elseif ($count > 3) {
            $this->flags[] = [
                'check'    => 'Subdomains',
                'status'   => 'warn',
                'message'  => "Multiple subdomains detected ({$this->host}) — inspect the real domain carefully",
                'severity' => 'medium',
            ];
            $this->score += 10;

        } else {
            $this->flags[] = [
                'check'    => 'Subdomains',
                'status'   => 'pass',
                'message'  => 'Subdomain count looks normal',
                'severity' => 'none',
            ];
        }
    }
}