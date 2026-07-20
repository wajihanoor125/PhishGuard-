<?php

namespace App\Http\Controllers;

use App\Models\UrlSubmit;
use App\Rules\NoLocalNetwork;
use App\Services\UrlPatternAnalyzer;
use App\Services\VirusTotalService;
use App\Services\GoogleSafeBrowsingService;
use App\Services\DomainAgeService;
use App\Services\BrandImpersonationService;
use Barryvdh\DomPDF\Facade\Pdf;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use App\Jobs\ProcessVirusTotalScan;
class UrlSubmitController extends Controller
{
    public function scan(Request $request)
    {
        set_time_limit(120); // give the scan 2 minutes max
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
                   ->whereRaw("JSON_UNQUOTE(JSON_EXTRACT(virustotal_result, '$.status')) = 'success'")
                   ->first();

        if ($cached) {
            return response()->json([
                'scan_id'                    => $cached->id,
                'share_token'                => $cached->share_token,
                'source'                     => 'cache',
                'url'                        => $cached->url,
                'domain'                     => $cached->domain,
                'verdict'                    => $cached->verdict,
                'risk_score'                 => $cached->risk_score,
                'virustotal_result'          => $cached->virustotal_result,
                'google_sb_result'           => $cached->google_sb_result,
                'domain_age_result'          => $cached->domain_age_result,
                'pattern_result'             => $cached->pattern_result,
                'brand_impersonation_result' => $cached->brand_impersonation_result,
                'scanned_at'                 => $cached->created_at,
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
        // ─── Step 4: Run fast checks synchronously ────────────────────────
$googleResult  = (new GoogleSafeBrowsingService())->scan($url);
$domainResult  = (new DomainAgeService())->scan($url);
$patternResult = (new UrlPatternAnalyzer())->analyze($url);
$brandResult   = (new BrandImpersonationService())->analyze($url);

// ─── Step 5: Calculate score WITHOUT VT (VT runs async) ──────────
$totalScore  = 0;
$totalScore += $googleResult['risk_score']  ?? 0;
$totalScore += $domainResult['risk_score']  ?? 0;
$totalScore += $patternResult['risk_score'] ?? 0;
$totalScore += $brandResult['risk_score']   ?? 0;
$totalScore  = min($totalScore, 100);

$verdict    = $this->calculateVerdict($totalScore);
$shareToken = Str::random(32);

// ─── Step 6: Save without VT result — job will update it ─────────
$scan->update([
    'virustotal_result'          => ['status' => 'pending', 'risk_score' => 0],
    'google_sb_result'           => $googleResult,
    'domain_age_result'          => $domainResult,
    'pattern_result'             => $patternResult,
    'brand_impersonation_result' => $brandResult,
    'risk_score'                 => $totalScore,
    'verdict'                    => $verdict,
    'share_token'                => $shareToken,
]);

// ─── Step 7: Dispatch VT job to queue ────────────────────────────
ProcessVirusTotalScan::dispatch($scan->id, $url);

// ─── Step 8: Return immediately — VT will update in background ───
return response()->json([
    'scan_id'                    => $scan->id,
    'share_token'                => $shareToken,
    'source'                     => 'fresh',
    'url'                        => $scan->url,
    'domain'                     => $scan->domain,
    'verdict'                    => $verdict,
    'risk_score'                 => $totalScore,
    'virustotal_result'          => ['status' => 'pending', 'risk_score' => 0],
    'google_sb_result'           => $googleResult,
    'domain_age_result'          => $domainResult,
    'pattern_result'             => $patternResult,
    'brand_impersonation_result' => $brandResult,
    'scanned_at'                 => $scan->created_at,
]);
    }
    

    // ─── Report Download ──────────────────────────────────────────────
    public function downloadReport($id)
    {
        $scan = UrlSubmit::findOrFail($id);

        $pdf = Pdf::loadView('pdf.scan-report', ['scan' => $scan])
                  ->setPaper('a4', 'portrait');

        return $pdf->download("phishguard-report-{$scan->id}.pdf");
    }

    private function calculateVerdict(int $score): string
    {
        if ($score >= 70) return 'malicious';
        if ($score >= 40) return 'suspicious';
        if ($score >= 15) return 'caution';
        return 'safe';
    }









    public function vtStatus(int $id): \Illuminate\Http\JsonResponse
{
    $scan = UrlSubmit::findOrFail($id);
    $vt   = $scan->virustotal_result;

    return response()->json([
        'scan_id'           => $scan->id,
        'vt_ready'          => isset($vt['status']) && $vt['status'] !== 'pending',
        'virustotal_result' => $vt,
        'risk_score'        => $scan->risk_score,
        'verdict'           => $scan->verdict,
    ]);
}
}