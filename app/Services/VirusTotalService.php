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

    // ─── Main Method — Call This From Controller ──────────────────────

    public function scan(string $url): array
    {
        try {
            // Step 1: Submit URL and get analysis ID
            $analysisId = $this->submitUrl($url);

            if (!$analysisId) {
                return $this->errorResponse('Failed to submit URL to VirusTotal');
            }

            // Step 2: Poll for results using that ID
            $result = $this->fetchResults($analysisId);

            return $result;

        } catch (\Exception $e) {
            Log::error('VirusTotal scan failed: ' . $e->getMessage());
            return $this->errorResponse($e->getMessage());
        }
    }

    // ─── Step 1: Submit URL to VirusTotal ────────────────────────────

    private function submitUrl(string $url): ?string
    {
        $response = Http::withHeaders([
            'x-apikey'     => $this->apiKey,
            'Content-Type' => 'application/x-www-form-urlencoded',
        ])->asForm()->post("{$this->baseUrl}/urls", [
            'url' => $url,
        ]);

        if ($response->failed()) {
            Log::error('VirusTotal submit failed', [
                'status' => $response->status(),
                'body'   => $response->body(),
            ]);
            return null;
        }

        // VirusTotal returns the analysis ID inside data.id
        return $response->json('data.id');
    }

    // ─── Step 2: Fetch Results Using Analysis ID ─────────────────────

    private function fetchResults(string $analysisId): array
    {
        $maxAttempts = 10;   // try max 10 times
        $waitSeconds = 3;    // wait 3 seconds between each attempt

        for ($attempt = 1; $attempt <= $maxAttempts; $attempt++) {

            $response = Http::withHeaders([
                'x-apikey' => $this->apiKey,
            ])->get("{$this->baseUrl}/analyses/{$analysisId}");

            if ($response->failed()) {
                return $this->errorResponse('Failed to fetch analysis results');
            }

            $data   = $response->json();
            $status = $data['data']['attributes']['status'] ?? 'pending';

            // VirusTotal returns "completed" when all engines are done
            if ($status === 'completed') {
                return $this->formatResult($data);
            }

            // Not ready yet — wait and try again
            if ($attempt < $maxAttempts) {
                sleep($waitSeconds);
            }
        }

        return $this->errorResponse('VirusTotal analysis timed out — try again');
    }

    // ─── Format The Raw Response Into Your Clean Structure ───────────

    private function formatResult(array $data): array
    {
        $stats = $data['data']['attributes']['stats'] ?? [];

        $malicious  = $stats['malicious']  ?? 0;
        $suspicious = $stats['suspicious'] ?? 0;
        $harmless   = $stats['harmless']   ?? 0;
        $undetected = $stats['undetected'] ?? 0;
        $total      = $malicious + $suspicious + $harmless + $undetected;

        // Individual engine results — useful for showing detail
        $engineResults = $data['data']['attributes']['results'] ?? [];

        // Only pull engines that actually flagged something
        $flaggedEngines = collect($engineResults)
            ->filter(fn($engine) => in_array($engine['category'], ['malicious', 'suspicious']))
            ->map(fn($engine, $name) => [
                'engine'   => $name,
                'category' => $engine['category'],
                'result'   => $engine['result'],
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

    // ─── Risk Score From VirusTotal (max 50 points) ───────────────────

    private function calculateScore(int $malicious, int $suspicious, int $total): int
    {
        if ($total === 0) return 0;

        $maliciousWeight  = ($malicious  / $total) * 50;
        $suspiciousWeight = ($suspicious / $total) * 20;

        return (int) min($maliciousWeight + $suspiciousWeight, 50);
    }

    // ─── Verdict Based On Engine Count ───────────────────────────────

    private function getVerdict(int $malicious, int $suspicious): string
    {
        if ($malicious >= 5)  return 'malicious';
        if ($malicious >= 1)  return 'suspicious';
        if ($suspicious >= 3) return 'suspicious';
        if ($suspicious >= 1) return 'caution';
        return 'safe';
    }

    // ─── Human Readable Summary ───────────────────────────────────────

    private function getSummary(int $malicious, int $suspicious, int $total): string
    {
        if ($malicious > 0) {
            return "{$malicious} out of {$total} security engines flagged this URL as malicious";
        }
        if ($suspicious > 0) {
            return "{$suspicious} out of {$total} security engines found this URL suspicious";
        }
        return "No security engines flagged this URL out of {$total} checked";
    }

    // ─── Error Structure ─────────────────────────────────────────────

    private function errorResponse(string $message): array
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