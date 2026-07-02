<?php
use Illuminate\Support\Facades\Http;

$response = Http::post(
    'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . env('SAFE_BROWSING_API_KEY'),
    [
        "client" => [
            "clientId" => "phishguardpk",
            "clientVersion" => "1.0"
        ],
        "threatInfo" => [
            "threatTypes" => [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes" => [
                "ANY_PLATFORM"
            ],
            "threatEntryTypes" => [
                "URL"
            ],
            "threatEntries" => [
                [
                    "url" => $url
                ]
            ]
        ]
    ]
);
