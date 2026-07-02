<?php

namespace App\Http\Controllers;
use App\Models\UrlSubmit;
use App\Rules\NoLocalNetwork;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use App\Services\UrlPatternAnalyzer;


class UrlSubmitController extends Controller
{
    public function scan(Request $request)
    {
        // Step 1 — Validate
        $request->validate([
            'url' => [
                'required',
                'string',
                'max:2048',
                'url:http,https',
                new NoLocalNetwork(),
            ]
        ]);
        // Step 2 — Generate hash
        $url  = $request->input('url');
        $hash = hash('sha256', $url);
        // Step 3 — Check cache (same URL scanned in last 24 hours)
        $cached = UrlSubmit::where('url_hash', $hash)->where('created_at', '>=', now()->subHours(24))->first();
        if ($cached) {
            return response()->json($cached); 
        }
        // Step 4 — Save to DB (you'll fill results after API calls)
        $scan = UrlSubmit::create([
            'url'        => $url,
            'url_hash'   => $hash,
            'domain'     => parse_url($url, PHP_URL_HOST),
            'ip_address' => $request->ip(),
            'verdict'    => 'safe',   
            'risk_score' => 0,        
        ]);


$analyzer = new UrlPatternAnalyzer();
$patternResult = $analyzer->analyze($url);

        return response()->json($scan);
    }
}