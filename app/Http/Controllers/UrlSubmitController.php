<?php

namespace App\Http\Controllers;

use App\Models\UrlSubmit;
use App\Rules\NoLocalNetwork;
use App\Services\UrlPatternAnalyzer;
use App\Services\VirusTotalService;
use App\Services\GoogleSafeBrowsingService;
use App\Services\DomainAgeService;
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
                           ->whereNotNull('virustotal_result')
                           ->whereNotNull('google_sb_result')
                           ->first();

        if ($cached) {
            return response()->json([
                'source'            => 'cache',
                'url'               => $cached->url,
                'domain'            => $cached->domain,
                'verdict'           => $cached->verdict,
                'risk_score'        => $cached->risk_score,
                'virustotal_result' => $cached->virustotal_result,
                'pattern_result'    => $cached->brand_impersonation_result,
                'google_sb_result'  => $cached->google_sb_result,
                'domain_age_result' => $cached->domain_age_result,
                'scanned_at'        => $cached->created_at,
            ]);
        }

        // ─── Step 3: Create Initial Record ───────────────────────────
        $scan = UrlSubmit::create([
            'url'        => $url,
            'url_hash'   => $hash,
            'domain'     => parse_url($url, PHP_URL_HOST),
            'ip_address' => $request->ip(),
            'verdict'    => 'safe',
            'risk_score' => 0,
        ]);

        // ─── Step 4: Run All 4 Checks ─────────────────────────────────
        $vtResult      = (new VirusTotalService())->scan($url);
        $googleResult  = (new GoogleSafeBrowsingService())->scan($url);
        $domainResult  = (new DomainAgeService())->scan($url);
        $patternResult = (new UrlPatternAnalyzer())->analyze($url);

        // ─── Step 5: Calculate Final Score ───────────────────────────
        $totalScore  = 0;
        $totalScore += $vtResult['risk_score']     ?? 0; // max 50
        $totalScore += $googleResult['risk_score'] ?? 0; // max 40
        $totalScore += $domainResult['risk_score'] ?? 0; // max 30
        $totalScore += $patternResult['risk_score'] ?? 0; // max 40
        $totalScore  = min($totalScore, 100);

        $verdict = $this->calculateVerdict($totalScore);

        // ─── Step 6: Save All Results ─────────────────────────────────
        $scan->update([
            'virustotal_result'          => $vtResult,
            'google_sb_result'           => $googleResult,
            'domain_age_result'          => $domainResult,
            'brand_impersonation_result' => $patternResult,
            'risk_score'                 => $totalScore,
            'verdict'                    => $verdict,
        ]);

        // ─── Step 7: Return Response ──────────────────────────────────
        return response()->json([
            'source'            => 'fresh',
            'url'               => $scan->url,
            'domain'            => $scan->domain,
            'verdict'           => $verdict,
            'risk_score'        => $totalScore,
            'virustotal_result' => $vtResult,
            'pattern_result'    => $patternResult,
            'google_sb_result'  => $googleResult,
            'domain_age_result' => $domainResult,
            'scanned_at'        => $scan->created_at,
        ]);
    }

    private function calculateVerdict(int $score): string
    {
        if ($score >= 70) return 'malicious';
        if ($score >= 40) return 'suspicious';
        if ($score >= 15) return 'caution';
        return 'safe';
    }
}