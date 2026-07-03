<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Carbon\Carbon;

class DomainAgeService
{
    public function scan(string $url): array
    {
        try {
            $domain = parse_url($url, PHP_URL_HOST);
            $domain = preg_replace('/^www\./', '', $domain);

            // Using whoisjson free API
            $response = Http::timeout(10)
                            ->get("https://whoisjson.com/api/v1/whois", [
                                'domain' => $domain,
                            ]);

            if ($response->failed()) {
                Log::error('WHOIS lookup failed', [
                    'domain' => $domain,
                    'status' => $response->status(),
                ]);
                return $this->errorResponse($domain);
            }

            $data        = $response->json();
            $createdRaw  = $data['created'] ?? $data['creation_date'] ?? null;

            if (!$createdRaw) {
                return $this->unknownAgeResponse($domain);
            }

            // Handle array — some WHOIS returns multiple dates
            if (is_array($createdRaw)) {
                $createdRaw = $createdRaw[0];
            }

            $createdDate = Carbon::parse($createdRaw);
            $ageInDays   = (int) $createdDate->diffInDays(now());
            $ageInYears  = round($ageInDays / 365, 1);
            $isNew       = $ageInDays < 180; // under 6 months = suspicious

            return [
                'status'      => 'success',
                'domain'      => $domain,
                'created_on'  => $createdDate->toDateString(),
                'age_days'    => $ageInDays,
                'age_human'   => $ageInDays < 365
                    ? "{$ageInDays} days"
                    : "{$ageInYears} years",
                'is_new'      => $isNew,
                'registrar'   => $data['registrar'] ?? 'Unknown',
                'risk_score'  => $this->calculateScore($ageInDays),
                'verdict'     => $isNew ? 'suspicious' : 'safe',
                'summary'     => $this->getSummary($domain, $ageInDays, $isNew),
            ];

        } catch (\Exception $e) {
            Log::error('Domain Age exception: ' . $e->getMessage());
            return $this->errorResponse(parse_url($url, PHP_URL_HOST) ?? '');
        }
    }

    private function calculateScore(int $ageInDays): int
    {
        if ($ageInDays < 7)   return 30; // under 1 week — very suspicious
        if ($ageInDays < 30)  return 25; // under 1 month
        if ($ageInDays < 90)  return 20; // under 3 months
        if ($ageInDays < 180) return 10; // under 6 months
        return 0;                         // established domain — no risk
    }

    private function getSummary(string $domain, int $ageInDays, bool $isNew): string
    {
        if ($isNew) {
            return "Domain '{$domain}' was registered only {$ageInDays} days ago — newly registered domains are a major phishing indicator";
        }
        return "Domain '{$domain}' has been active for {$ageInDays} days — established domain";
    }

    private function unknownAgeResponse(string $domain): array
    {
        return [
            'status'     => 'unknown',
            'domain'     => $domain,
            'created_on' => null,
            'age_days'   => null,
            'age_human'  => 'Unknown',
            'is_new'     => false,
            'registrar'  => 'Unknown',
            'risk_score' => 5,
            'verdict'    => 'caution',
            'summary'    => "Could not determine registration date for '{$domain}'",
        ];
    }

    private function errorResponse(string $domain): array
    {
        return [
            'status'     => 'error',
            'domain'     => $domain,
            'created_on' => null,
            'age_days'   => null,
            'age_human'  => 'Unknown',
            'is_new'     => false,
            'registrar'  => 'Unknown',
            'risk_score' => 0,
            'verdict'    => 'unknown',
            'summary'    => 'Domain age check could not be completed',
        ];
    }
}