<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Carbon\Carbon;

class DomainAgeService
{
    private string $domain;
    private string $apiKey;

    public function __construct()
    {
        $this->apiKey = config('services.whoapi.key');
    }

    // ─── Main Entry Point ─────────────────────────────────────────────

    public function scan(string $url): array
    {
        $host         = parse_url($url, PHP_URL_HOST) ?? '';
        $this->domain = strtolower(preg_replace('/^www\./', '', $host));

        // Try WhoAPI first
        $result = $this->tryWhoApi();
        if ($result) return $result;

        // Fallback to RDAP (free, no key needed)
        $result = $this->tryRdap();
        if ($result) return $result;

        // Both failed
        Log::warning("Domain age: all sources failed for {$this->domain}");
        return $this->unknownResponse();
    }

    // ─── Source 1: WhoAPI 
    private function tryWhoApi(): ?array
    {
        try {
            $response = Http::timeout(10)->get('https://api.whoapi.com/', [
                'domain' => $this->domain,
                'r'      => 'whois',
                'apikey' => $this->apiKey,
            ]);

            if ($response->failed()) {
                Log::warning("WhoAPI request failed for {$this->domain}: " . $response->status());
                return null;
            }

            $data = $response->json();

            // WhoAPI returns status 0 for success
            if (($data['status'] ?? '') !== '0') {
                Log::warning("WhoAPI returned non-success status for {$this->domain}", [
                    'status'  => $data['status']  ?? 'none',
                    'message' => $data['status_desc'] ?? 'none',
                ]);
                return null;
            }

            // WhoAPI stores creation date in date_created
            $createdRaw = $data['date_created'] ?? null;

            if (!$createdRaw || $createdRaw === '0000-00-00') {
                Log::warning("WhoAPI: no creation date for {$this->domain}");
                return null;
            }

            $registrar = $data['registrar_name'] ?? 'Unknown';

            return $this->buildResult($createdRaw, $registrar, 'whoapi');

        } catch (\Exception $e) {
            Log::error("WhoAPI exception for {$this->domain}: " . $e->getMessage());
            return null;
        }
    }

    // ─── Source 2: RDAP Fallback (Free, No Key)
    private function tryRdap(): ?array
    {
        try {
            $response = Http::timeout(8)
                            ->get("https://rdap.org/domain/{$this->domain}");

            if ($response->failed()) {
                Log::warning("RDAP failed for {$this->domain}: " . $response->status());
                return null;
            }

            $data   = $response->json();
            $events = $data['events'] ?? [];

            // RDAP stores dates inside events array
            $createdRaw = null;
            foreach ($events as $event) {
                if (($event['eventAction'] ?? '') === 'registration') {
                    $createdRaw = $event['eventDate'] ?? null;
                    break;
                }
            }

            if (!$createdRaw) return null;

            // Extract registrar from entities
            $registrar = 'Unknown';
            foreach ($data['entities'] ?? [] as $entity) {
                if (in_array('registrar', $entity['roles'] ?? [])) {
                    $registrar = $entity['vcardArray'][1][1][3]
                              ?? $entity['handle']
                              ?? 'Unknown';
                    break;
                }
            }

            return $this->buildResult($createdRaw, $registrar, 'rdap');

        } catch (\Exception $e) {
            Log::error("RDAP exception for {$this->domain}: " . $e->getMessage());
            return null;
        }
    }

    // ─── Build Clean Result From Either Source ────────────────────────

    private function buildResult(string $createdRaw, string $registrar, string $source): ?array
    {
        try {
            $createdDate = Carbon::parse($createdRaw);
            $ageInDays   = (int) $createdDate->diffInDays(now());
            $isNew       = $ageInDays < 180;

            $ageHuman = $ageInDays < 365
                ? "{$ageInDays} days"
                : round($ageInDays / 365, 1) . ' years';

            return [
                'status'     => 'success',
                'domain'     => $this->domain,
                'created_on' => $createdDate->toDateString(),
                'age_days'   => $ageInDays,
                'age_human'  => $ageHuman,
                'is_new'     => $isNew,
                'registrar'  => $registrar,
                'source'     => $source,
                'risk_score' => $this->calculateScore($ageInDays),
                'verdict'    => $isNew ? 'suspicious' : 'safe',
                'summary'    => $this->getSummary($ageInDays, $isNew),
            ];

        } catch (\Exception $e) {
            Log::error("Failed to parse date '{$createdRaw}': " . $e->getMessage());
            return null;
        }
    }    // ─── Risk Score ───────────────────────────────────────────────────

    private function calculateScore(int $ageInDays): int
    {
        if ($ageInDays < 7)   return 30; // under 1 week
        if ($ageInDays < 30)  return 25; // under 1 month
        if ($ageInDays < 90)  return 20; // under 3 months
        if ($ageInDays < 180) return 10; // under 6 months
        return 0;                         // established domain
    }   // ─── Summary Text ─────────────────────────────────────────────────

    private function getSummary(int $ageInDays, bool $isNew): string
    {
        if ($isNew) {
            return "Domain was registered only {$ageInDays} days ago — newly registered domains are a strong phishing indicator";
        }
        return "Domain has been active for {$ageInDays} days — this is an established domain";
    }

    // ─── Unknown Response 
    private function unknownResponse(): array
    {
        return [
            'status'     => 'unknown',
            'domain'     => $this->domain,
            'created_on' => null,
            'age_days'   => null,
            'age_human'  => 'Unknown',
            'is_new'     => false,
            'registrar'  => 'Unknown',
            'source'     => null,
            'risk_score' => 5,
            'verdict'    => 'caution',
            'summary'    => "Could not determine registration date for '{$this->domain}'",
        ];
    }
}