<?php

namespace App\Jobs;

use App\Models\UrlSubmit;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Http\Client\RequestException;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;

class ProcessVirusTotalScan implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    // ── Job config ────────────────────────────────────────────────────
    public int $tries   = 5;    // retry up to 5 times total
    public int $timeout = 120;  // max 2 minutes per attempt

    private string $baseUrl = 'https://www.virustotal.com/api/v3';
    private string $apiKey;

    public function __construct(
        private readonly int    $scanId,
        private readonly string $url
    ) {
        $this->apiKey = config('services.virustotal.key');
    }

    // ── Main handle ───────────────────────────────────────────────────
    public function handle(): void
    {
        $rateLimitKey = 'virustotal-api-calls';

        // ── RateLimiter: max 4 calls per 60 seconds ───────────────────
        $allowed = RateLimiter::attempt(
            key:      $rateLimitKey,
            maxAttempts: 4,
            callback: function () {},
            decaySeconds: 60
        );

        if (!$allowed) {
            $availableIn = RateLimiter::availableIn($rateLimitKey);
            Log::info("VT Job: Rate limit reached. Releasing back to queue. Available in {$availableIn}s.");

            // Release back to queue — retry after limit resets
            $this->release($availableIn + 2);
            return;
        }

        // ── Step 1: Submit URL to VT ──────────────────────────────────
        $analysisId = $this->submitUrl();

        if (!$analysisId) {
            $this->saveResult($this->errorResponse('Failed to submit URL to VirusTotal'));
            return;
        }

        // ── Step 2: Poll for results ──────────────────────────────────
        $result = $this->pollForResults($analysisId);
        $this->saveResult($result);
    }

    // ── Submit URL ────────────────────────────────────────────────────
    private function submitUrl(): ?string
    {
        try {
            $response = Http::withHeaders([
                'x-apikey'     => $this->apiKey,
                'Content-Type' => 'application/x-www-form-urlencoded',
            ])
            ->connectTimeout(10)  // connection must establish in 10s
            ->timeout(30)         // full request must complete in 30s
            ->asForm()
            ->post("{$this->baseUrl}/urls", ['url' => $this->url]);

            // ── 429: rate limited at HTTP level ───────────────────────
            if ($response->status() === 429) {
                Log::warning("VT Job: HTTP 429 on submit. Releasing to queue.");
                $this->release(30);
                return null;
            }

            if ($response->failed()) {
                Log::error("VT Job: Submit failed. Status: {$response->status()}");
                return null;
            }

            return $response->json('data.id');

        } catch (RequestException $e) {
            Log::error('VT Job: Submit request exception — ' . $e->getMessage());
            return null;
        } catch (\Exception $e) {
            Log::error('VT Job: Submit general exception — ' . $e->getMessage());
            return null;
        }
    }

    // ── Poll for completed results ────────────────────────────────────
    private function pollForResults(string $analysisId): array
    {
        $maxAttempts = 10;
        $waitSeconds = 5;

        for ($attempt = 1; $attempt <= $maxAttempts; $attempt++) {
            try {
                $response = Http::withHeaders([
                    'x-apikey' => $this->apiKey,
                ])
                ->connectTimeout(10)
                ->timeout(30)      // 30s Guzzle timeout per poll request
                ->get("{$this->baseUrl}/analyses/{$analysisId}");

                // ── 429 during polling ────────────────────────────────
                if ($response->status() === 429) {
                    Log::warning("VT Job: HTTP 429 on poll attempt {$attempt}. Releasing.");
                    $this->release(30);
                    return $this->pendingResponse();
                }

                if ($response->failed()) {
                    Log::error("VT Job: Poll failed. Status: {$response->status()}");
                    return $this->errorResponse("Poll failed: {$response->status()}");
                }

                $data   = $response->json();
                $status = $data['data']['attributes']['status'] ?? 'pending';

                if ($status === 'completed') {
                    Log::info("VT Job: Analysis completed on attempt {$attempt}.");
                    return $this->formatResult($data);
                }

                Log::info("VT Job: Status '{$status}' on attempt {$attempt}. Waiting {$waitSeconds}s.");

                if ($attempt < $maxAttempts) {
                    sleep($waitSeconds);
                }

            } catch (RequestException $e) {
                Log::error("VT Job: Poll request exception on attempt {$attempt} — " . $e->getMessage());
                return $this->errorResponse($e->getMessage());
            } catch (\Exception $e) {
                Log::error("VT Job: Poll general exception — " . $e->getMessage());
                return $this->errorResponse($e->getMessage());
            }
        }

        return $this->errorResponse('VirusTotal analysis timed out after maximum polling attempts');
    }

    // ── Save result back to the scan record ──────────────────────────
    private function saveResult(array $result): void
    {
        $scan = UrlSubmit::find($this->scanId);

        if (!$scan) {
            Log::error("VT Job: Scan record #{$this->scanId} not found.");
            return;
        }

        // Recalculate total score with real VT result
        $vtScore      = $result['risk_score'] ?? 0;
        $currentScore = $scan->risk_score ?? 0;

        // Add VT score on top of existing score (capped at 100)
        $newScore = min($currentScore + $vtScore, 100);
        $verdict  = $this->calculateVerdict($newScore);

        $scan->update([
            'virustotal_result' => $result,
            'risk_score'        => $newScore,
            'verdict'           => $verdict,
        ]);

        Log::info("VT Job: Saved result for scan #{$this->scanId}. Score: {$newScore}. Verdict: {$verdict}.");
    }

    // ── Format VT response ────────────────────────────────────────────
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
            'risk_score'      => $this->calculateVtScore($malicious, $suspicious, $total),
            'verdict'         => $this->getVtVerdict($malicious, $suspicious),
            'summary'         => $this->getSummary($malicious, $suspicious, $total),
        ];
    }

    // ── Helpers ───────────────────────────────────────────────────────
    private function calculateVtScore(int $malicious, int $suspicious, int $total): int
    {
        if ($total === 0) return 0;
        return (int) min(($malicious / $total) * 50 + ($suspicious / $total) * 20, 50);
    }

    private function getVtVerdict(int $malicious, int $suspicious): string
    {
        if ($malicious >= 5)  return 'malicious';
        if ($malicious >= 1)  return 'suspicious';
        if ($suspicious >= 3) return 'suspicious';
        if ($suspicious >= 1) return 'caution';
        return 'safe';
    }

    private function getSummary(int $malicious, int $suspicious, int $total): string
    {
        if ($malicious > 0) return "{$malicious} out of {$total} engines flagged this URL as malicious";
        if ($suspicious > 0) return "{$suspicious} out of {$total} engines found this URL suspicious";
        return "No engines flagged this URL out of {$total} checked";
    }

    private function calculateVerdict(int $score): string
    {
        if ($score >= 70) return 'malicious';
        if ($score >= 40) return 'suspicious';
        if ($score >= 15) return 'caution';
        return 'safe';
    }

    private function pendingResponse(): array
    {
        return [
            'status'          => 'pending',
            'malicious'       => 0,
            'suspicious'      => 0,
            'harmless'        => 0,
            'undetected'      => 0,
            'total_engines'   => 0,
            'flagged_engines' => [],
            'risk_score'      => 0,
            'verdict'         => 'pending',
            'summary'         => 'VirusTotal analysis is queued — check back shortly',
        ];
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

    // ── Called when all retries exhausted ────────────────────────────
    public function failed(\Throwable $exception): void
    {
        Log::error("VT Job: Permanently failed for scan #{$this->scanId} — " . $exception->getMessage());

        $scan = UrlSubmit::find($this->scanId);
        if ($scan) {
            $scan->update([
                'virustotal_result' => $this->errorResponse('Job permanently failed after retries'),
            ]);
        }
    }
}