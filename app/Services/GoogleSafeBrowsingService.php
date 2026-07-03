<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class GoogleSafeBrowsingService
{
    private string $apiKey;
    private string $baseUrl = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

    public function __construct()
    {
        $this->apiKey = config('services.google.safe_browsing_key');
    }

    public function scan(string $url): array
    {
        try {
            $response = Http::post("{$this->baseUrl}?key={$this->apiKey}", [
                'client' => [
                    'clientId'      => 'phishguard-pk',
                    'clientVersion' => '1.0.0',
                ],
                'threatInfo' => [
                    'threatTypes' => [
                        'MALWARE',
                        'SOCIAL_ENGINEERING',
                        'UNWANTED_SOFTWARE',
                        'POTENTIALLY_HARMFUL_APPLICATION',
                    ],
                    'platformTypes'    => ['ANY_PLATFORM'],
                    'threatEntryTypes' => ['URL'],
                    'threatEntries'    => [['url' => $url]],
                ],
            ]);

            if ($response->failed()) {
                Log::error('Google Safe Browsing failed', [
                    'status' => $response->status(),
                    'body'   => $response->body(),
                ]);
                return $this->errorResponse();
            }

            $matches = $response->json('matches') ?? [];
            $flagged = count($matches) > 0;

            $threats = collect($matches)->map(fn($match) => [
                'type'     => $match['threatType']     ?? 'Unknown',
                'platform' => $match['platformType']   ?? 'Unknown',
                'url'      => $match['threat']['url']  ?? $url,
            ])->toArray();

            return [
                'status'     => 'success',
                'flagged'    => $flagged,
                'threats'    => $threats,
                'risk_score' => $flagged ? 40 : 0,
                'verdict'    => $flagged ? 'malicious' : 'safe',
                'summary'    => $flagged
                    ? 'Google flagged this URL as an active threat'
                    : 'Google Safe Browsing found no threats',
            ];

        } catch (\Exception $e) {
            Log::error('Google Safe Browsing exception: ' . $e->getMessage());
            return $this->errorResponse();
        }
    }

    private function errorResponse(): array
    {
        return [
            'status'     => 'error',
            'flagged'    => false,
            'threats'    => [],
            'risk_score' => 0,
            'verdict'    => 'unknown',
            'summary'    => 'Google Safe Browsing check could not be completed',
        ];
    }
}