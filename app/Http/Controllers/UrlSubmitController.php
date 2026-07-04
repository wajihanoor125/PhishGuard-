<?php

namespace App\Http\Controllers;

use App\Models\UrlSubmit;
use App\Rules\NoLocalNetwork;
use App\Services\UrlPatternAnalyzer;
use App\Services\VirusTotalService;
use Illuminate\Http\Request;

class UrlSubmitController extends Controller
{
    public function scan(Request $request)
    {
        // ─── Step 1: Validate ─────────────────────────────────────────
        $request->validate([
            'url' => [
                'required',
                'string',
                'max:2048',
                'url:http,https',
                new NoLocalNetwork(),
            ]
        ]);

        $url  = $request->input('url');
        $hash = hash('sha256', $url);

        // ─── Step 2: Check Cache ──────────────────────────────────────
       $cached = UrlSubmit::where('url_hash', $hash)
                   ->where('created_at', '>=', now()->subHours(24))
                   ->whereNotNull('virustotal_result')  // must have real results
                   ->whereNotNull('google_sb_result')
                   ->first();

        if ($cached) {
            return response()->json([
                'source'                     => 'cache',
                'url'                        => $cached->url,
                'domain'                     => $cached->domain,
                'verdict'                    => $cached->verdict,
                'risk_score'                 => $cached->risk_score,
                'virustotal_result'          => $cached->virustotal_result,
                'pattern_result'             => $cached->brand_impersonation_result,
                'domain_age_result'          => $cached->domain_age_result,
                'google_sb_result'           => $cached->google_sb_result,
                'scanned_at'                 => $cached->created_at,
            ]);
        }

        // ─── Step 3: Create Initial DB Record ─────────────────────────
        // Save first with defaults — update after checks complete
        $scan = UrlSubmit::create([
            'url'        => $url,
            'url_hash'   => $hash,
            'domain'     => parse_url($url, PHP_URL_HOST),
            'ip_address' => $request->ip(),
            'verdict'    => 'safe',
            'risk_score' => 0,
        ]);

        // ─── Step 4: Run All 4 Checks ─────────────────────────────────

        // Check 1 — VirusTotal
        $virusTotal = new VirusTotalService();
        $vtResult   = $virusTotal->scan($url);
        $vtResult = $virusTotal->scan($url);
\Log::info('VT Result', ['result' => $vtResult]);

        // Check 2 — URL Pattern + Brand Impersonation
        $analyzer      = new UrlPatternAnalyzer();
        $patternResult = $analyzer->analyze($url);
        $patternResult = $analyzer->analyze($url);
\Log::info('Pattern Result', ['result' => $patternResult]);

        // Check 3 — Google Safe Browsing (add service when ready)
        $googleResult = [
            'status'  => 'pending',
            'flagged' => false,
            'threats' => [],
            'risk_score' => 0,
        ];

        // Check 4 — Domain Age (add service when ready)
        $domainAgeResult = [
            'status'     => 'pending',
            'age_days'   => null,
            'is_new'     => false,
            'risk_score' => 0,
        ];

        // ─── Step 5: Calculate Final Risk Score ───────────────────────
        $totalScore = 0;
        $totalScore += $vtResult['risk_score']        ?? 0; // max 50
        $totalScore += $patternResult['risk_score']   ?? 0; // max 40
        $totalScore += $googleResult['risk_score']    ?? 0; // max 30 (when built)
        $totalScore += $domainAgeResult['risk_score'] ?? 0; // max 20 (when built)
        $totalScore  = min($totalScore, 100);               // hard cap at 100

        // ─── Step 6: Calculate Final Verdict ─────────────────────────
        $verdict = $this->calculateVerdict($totalScore);

        // ─── Step 7: Update DB With All Results ───────────────────────
        $scan->update([
            'virustotal_result'          => $vtResult,
            'brand_impersonation_result' => $patternResult,
            'google_sb_result'           => $googleResult,
            'domain_age_result'          => $domainAgeResult,
            'risk_score'                 => $totalScore,
            'verdict'                    => $verdict,
        ]);

        // ─── Step 8: Return Final Response ────────────────────────────
        return response()->json([
            'source'             => 'fresh',
            'url'                => $scan->url,
            'domain'             => $scan->domain,
            'verdict'            => $verdict,
            'risk_score'         => $totalScore,
            'virustotal_result'  => $vtResult,
            'pattern_result'     => $patternResult,
            'google_sb_result'   => $googleResult,
            'domain_age_result'  => $domainAgeResult,
            'scanned_at'         => $scan->created_at,
        ]);
    }

    // ─── Verdict Logic ────────────────────────────────────────────────
    private function calculateVerdict(int $score): string
    {
        if ($score >= 70) return 'malicious';
        if ($score >= 40) return 'suspicious';
        if ($score >= 15) return 'caution';
        return 'safe';
    }
}