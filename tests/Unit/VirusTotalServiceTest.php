<?php

use App\Services\VirusTotalService;
use Illuminate\Support\Facades\Http;

describe('VirusTotalService', function () {
    it('keeps polling until the analysis completes', function () {
        Http::fake([
            'https://www.virustotal.com/api/v3/analyses/abc123' => Http::sequence()
                ->push([
                    'data' => [
                        'attributes' => [
                            'status' => 'queued',
                            'stats' => [],
                            'results' => [],
                        ],
                    ],
                ], 200)
                ->push([
                    'data' => [
                        'attributes' => [
                            'status' => 'completed',
                            'stats' => [
                                'malicious' => 1,
                                'suspicious' => 0,
                                'harmless' => 9,
                                'undetected' => 0,
                            ],
                            'results' => [],
                        ],
                    ],
                ], 200),
        ]);

        $service = new VirusTotalService('test-key', ['maxAttempts' => 2, 'waitSeconds' => 0]);

        $result = $service->fetchResults('abc123');

        expect($result['status'])->toBe('success');
        expect($result['malicious'])->toBe(1);
    });
});
