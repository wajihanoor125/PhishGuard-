<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class VirusTotalService
{
    private string $apiKey;
    private string $baseUrl = 'https://www.virustotal.com/api/v3';

    public function __construct()
    {
        $this->apiKey = config('services.virustotal.key');
    }

    // ─── Called by controller — Step 1: just submit, get ID back ─────
    public function submitUrl(string $url): ?string
    {
        try {
            // Check if VT already has a recent result for this URL
            $urlId    = rtrim(strtr(base64_encode($url), '+/', '-_'), '=');
            $existing = Http::withHeaders(['x-apikey' => $this->apiKey])
                            ->get("{$this->baseUrl}/urls/{$urlId}");

            if ($existing->successful()) {
                $lastAnalysis = $existing->json('data.attributes.last_analysis_date');
                $hoursAgo     = $lastAnalysis ? (time() - $lastAnalysis) / 3600 : 999;

                // VT scanned this within last 24hrs — return existing analysis ID
                if ($hoursAgo < 24) {
                    Log::info("VT: Using existing analysis for URL (scanned {$hoursAgo}h ago)");
                    return $existing->json('data.id') ?? $this->submitFresh($url);
                }
            }
        } catch (\Exception $e) {
            Log::warning('VT: Existing URL check failed, submitting fresh: ' . $e->getMessage());
        }

        return $this->submitFresh($url);
    }

    // ─── Called by controller — Step 2: poll after other checks run ──
   public function fetchResults(string $analysisId): array
{
    $maxAttempts = 8;
    $waitSeconds = 3;

    for ($attempt = 1; $attempt <= $maxAttempts; $attempt++) {
        try {
            $response = Http::withHeaders(['x-apikey' => $this->apiKey])
                            ->get("{$this->baseUrl}/analyses/{$analysisId}");

            // ── 429 goes HERE — right after the request, before anything else ──
            if ($response->status() === 429) {
                Log::warning('VT: Rate limit hit on attempt ' . $attempt);
                sleep(15); // wait 15 seconds then retry
                continue;  // skip the rest of this loop iteration, try again
            }

            if ($response->failed()) {
                return $this->errorResponse('VT analysis fetch failed: ' . $response->status());
            }

            $data   = $response->json();
            $status = $data['data']['attributes']['status'] ?? 'pending';

            if ($status === 'completed') {
                return $this->formatResult($data);
            }

            if ($attempt < $maxAttempts) {
                sleep($waitSeconds);
            }

        } catch (\Exception $e) {
            Log::error('VT fetchResults exception: ' . $e->getMessage());
            return $this->errorResponse($e->getMessage());
        }
    }

    return $this->errorResponse('VirusTotal rate limit reached — wait 1 minute and re-scan');
}
    // ─── Convenience method (not used by controller anymore) ─────────
    public function scan(string $url): array
    {
        $analysisId = $this->submitUrl($url);
        if (!$analysisId) {
            return $this->errorResponse('Failed to submit URL to VirusTotal');
        }
        return $this->fetchResults($analysisId);
    }

    // ─── Private: fresh submission ────────────────────────────────────
    private function submitFresh(string $url): ?string
    {
        try {
            $response = Http::withHeaders([
                'x-apikey'     => $this->apiKey,
                'Content-Type' => 'application/x-www-form-urlencoded',
            ])->asForm()->post("{$this->baseUrl}/urls", ['url' => $url]);

            if ($response->failed()) {
                Log::error('VT submit failed: ' . $response->status() . ' — ' . $response->body());
                return null;
            }

            return $response->json('data.id');

        } catch (\Exception $e) {
            Log::error('VT submitFresh exception: ' . $e->getMessage());
            return null;
        }
    }

    // ─── Format raw VT response ───────────────────────────────────────
    private function formatResult(array $data): array
    {
        $stats      = $data['data']['attributes']['stats'] ?? [];
        $malicious  = $stats['malicious']  ?? 0;
        $suspicious = $stats['suspicious'] ?? 0;
        $harmless   = $stats['harmless']   ?? 0;
        $undetected = $stats['undetected'] ?? 0;
        $total      = $malicious + $suspicious + $harmless + $undetected;

        $flaggedEngines = collect($data['data']['attributes']['results'] ?? [])
            ->filter(fn($e) => in_array($e['category'], ['malicious', 'suspicious']))
            ->map(fn($e, $name) => [
                'engine'   => $name,
                'category' => $e['category'],
                'result'   => $e['result'],
            ])
            ->values()
            ->toArray();

        return [
            'status'          => 'success',
            'malicious'       => $malicious,
            'suspicious'      => $suspicious,
            'harmless'        => $harmless,
            'undetected'      => $undetected,
            'total_engines'   => $total,
            'flagged_engines' => $flaggedEngines,
            'risk_score'      => $this->calculateScore($malicious, $suspicious, $total),
            'verdict'         => $this->getVerdict($malicious, $suspicious),
            'summary'         => $this->getSummary($malicious, $suspicious, $total),
        ];
    }

    private function calculateScore(int $malicious, int $suspicious, int $total): int
    {
        if ($total === 0) return 0;
        return (int) min(($malicious / $total) * 50 + ($suspicious / $total) * 20, 50);
    }

    private function getVerdict(int $malicious, int $suspicious): string
    {
        if ($malicious >= 5)  return 'malicious';
        if ($malicious >= 1)  return 'suspicious';
        if ($suspicious >= 3) return 'suspicious';
        if ($suspicious >= 1) return 'caution';
        return 'safe';
    }

    private function getSummary(int $malicious, int $suspicious, int $total): string
    {
        if ($malicious > 0) return "{$malicious} out of {$total} security engines flagged this URL as malicious";
        if ($suspicious > 0) return "{$suspicious} out of {$total} engines found this URL suspicious";
        return "No security engines flagged this URL out of {$total} checked";
    }

    public function errorResponse(string $message): array
    {
        return [
            'status'          => 'error',
            'message'         => $message,
            'malicious'       => 0,
            'suspicious'      => 0,
            'harmless'        => 0,
            'undetected'      => 0,
            'total_engines'   => 0,
            'flagged_engines' => [],
            'risk_score'      => 0,
            'verdict'         => 'unknown',
            'summary'         => 'VirusTotal check could not be completed',
        ];
    }
}