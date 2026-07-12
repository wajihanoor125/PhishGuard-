<?php

namespace App\Services;

class BrandImpersonationService
{
    // ─── Pakistani + International Brand Registry ─────────────────────
    private array $brands = [

        // ── Pakistani Banks ──────────────────────────────────────────
        [
            'name'     => 'HBL Bank',
            'keywords' => ['hbl', 'habibbank', 'habib-bank'],
            'official' => ['hbl.com', 'hblbank.com'],
        ],
        [
            'name'     => 'UBL Bank',
            'keywords' => ['ubl', 'unitedbank', 'united-bank'],
            'official' => ['ubl.com'],
        ],
        [
            'name'     => 'MCB Bank',
            'keywords' => ['mcb', 'muslimcommercial'],
            'official' => ['mcb.com.pk'],
        ],
        [
            'name'     => 'Meezan Bank',
            'keywords' => ['meezan', 'meezanbank'],
            'official' => ['meezanbank.com'],
        ],
        [
            'name'     => 'Askari Bank',
            'keywords' => ['askari', 'askaribank'],
            'official' => ['askaribank.com', 'askaribank.com.pk'],
        ],
        [
            'name'     => 'Bank Alfalah',
            'keywords' => ['alfalah', 'bankalfalah'],
            'official' => ['bankalfalah.com'],
        ],
        [
            'name'     => 'Allied Bank',
            'keywords' => ['abl', 'alliedbank', 'allied-bank'],
            'official' => ['abl.com'],
        ],
        [
            'name'     => 'Standard Chartered Pakistan',
            'keywords' => ['standardchartered', 'scbank'],
            'official' => ['sc.com'],
        ],

        // ── Pakistani Fintechs ────────────────────────────────────────
        [
            'name'     => 'EasyPaisa',
            'keywords' => ['easypaisa', 'easy-paisa', 'epaisa'],
            'official' => ['easypaisa.com'],
        ],
        [
            'name'     => 'JazzCash',
            'keywords' => ['jazzcash', 'jazz-cash', 'jcash'],
            'official' => ['jazzcash.com.pk'],
        ],
        [
            'name'     => 'NayaPay',
            'keywords' => ['nayapay', 'naya-pay'],
            'official' => ['nayapay.com'],
        ],
        [
            'name'     => 'SadaPay',
            'keywords' => ['sadapay', 'sada-pay'],
            'official' => ['sadapay.com'],
        ],

        // ── Pakistani Government ──────────────────────────────────────
        [
            'name'     => 'NADRA',
            'keywords' => ['nadra'],
            'official' => ['nadra.gov.pk'],
        ],
        [
            'name'     => 'FBR',
            'keywords' => ['fbr', 'federalboard'],
            'official' => ['fbr.gov.pk'],
        ],
        [
            'name'     => 'State Bank of Pakistan',
            'keywords' => ['sbp', 'statebank'],
            'official' => ['sbp.org.pk'],
        ],
        [
            'name'     => 'PTCL',
            'keywords' => ['ptcl'],
            'official' => ['ptcl.com.pk'],
        ],

        // ── Pakistani Telcos ──────────────────────────────────────────
        [
            'name'     => 'Jazz',
            'keywords' => ['jazz', 'jazzmobile'],
            'official' => ['jazz.com.pk'],
        ],
        [
            'name'     => 'Zong',
            'keywords' => ['zong'],
            'official' => ['zong.com.pk'],
        ],
        [
            'name'     => 'Telenor Pakistan',
            'keywords' => ['telenor'],
            'official' => ['telenor.com.pk'],
        ],
        [
            'name'     => 'Ufone',
            'keywords' => ['ufone'],
            'official' => ['ufone.com'],
        ],

        // ── Pakistani Commerce ────────────────────────────────────────
        [
            'name'     => 'Daraz',
            'keywords' => ['daraz'],
            'official' => ['daraz.pk'],
        ],
        [
            'name'     => 'Foodpanda Pakistan',
            'keywords' => ['foodpanda', 'food-panda'],
            'official' => ['foodpanda.pk'],
        ],

        // ── International ─────────────────────────────────────────────
        [
            'name'     => 'PayPal',
            'keywords' => ['paypal', 'pay-pal'],
            'official' => ['paypal.com'],
        ],
        [
            'name'     => 'Google',
            'keywords' => ['google', 'gmail', 'googl'],
            'official' => ['google.com', 'gmail.com', 'google.com.pk'],
        ],
        [
            'name'     => 'Microsoft',
            'keywords' => ['microsoft', 'microsft', 'outlook', 'hotmail'],
            'official' => ['microsoft.com', 'outlook.com', 'hotmail.com', 'live.com'],
        ],
        [
            'name'     => 'Facebook / Meta',
            'keywords' => ['facebook', 'facebok', 'meta'],
            'official' => ['facebook.com', 'meta.com'],
        ],
        [
            'name'     => 'Amazon',
            'keywords' => ['amazon', 'amazn'],
            'official' => ['amazon.com'],
        ],
        [
            'name'     => 'Apple',
            'keywords' => ['apple', 'icloud', 'itunes'],
            'official' => ['apple.com', 'icloud.com'],
        ],
    ];

    // ─── Main Entry Point ─────────────────────────────────────────────

    public function analyze(string $url): array
    {
        $host   = strtolower(parse_url($url, PHP_URL_HOST) ?? '');
        $domain = preg_replace('/^www\./', '', $host);
        $path   = strtolower(parse_url($url, PHP_URL_PATH) ?? '');

        foreach ($this->brands as $brand) {

            // ── Technique 1: Exact official domain match ──────────────
            // If it IS the real domain, immediately return clean result
            foreach ($brand['official'] as $official) {
                if ($domain === $official || $host === $official) {
                    return $this->safeResult($brand['name'], $domain);
                }
            }

            // ── Technique 2: Keyword found in domain ──────────────────
            foreach ($brand['keywords'] as $keyword) {
                if (str_contains($domain, $keyword)) {
                    return $this->impersonationResult(
                        $brand,
                        $domain,
                        'keyword_in_domain',
                        35,
                        "Domain contains '{$keyword}' but is not {$brand['name']}'s official website"
                    );
                }
            }

            // ── Technique 3: Typosquatting (Levenshtein check) ────────
            foreach ($brand['official'] as $official) {
                // Strip TLD for comparison to avoid false positives
                $officialStripped = explode('.', $official)[0];
                $domainStripped   = explode('.', $domain)[0];

                $distance = levenshtein($domainStripped, $officialStripped);

                if ($distance > 0 && $distance <= 2 && strlen($domainStripped) > 3) {
                    return $this->impersonationResult(
                        $brand,
                        $domain,
                        'typosquatting',
                        40,
                        "'{$domain}' is suspiciously similar to {$brand['name']}'s official domain '{$official}' — possible typosquatting"
                    );
                }
            }

            // ── Technique 4: Official brand domain used as subdomain ──
            // e.g. hbl.com.verify-now.net
            foreach ($brand['official'] as $official) {
                if (str_contains($host, $official . '.')) {
                    return $this->impersonationResult(
                        $brand,
                        $domain,
                        'subdomain_trick',
                        30,
                        "'{$host}' uses {$brand['name']}'s official domain as a subdomain to appear legitimate"
                    );
                }
            }

            // ── Technique 5: Brand keyword only in URL path ───────────
            foreach ($brand['keywords'] as $keyword) {
                if (!str_contains($domain, $keyword) && str_contains($path, $keyword)) {
                    return $this->impersonationResult(
                        $brand,
                        $domain,
                        'keyword_in_path',
                        15,
                        "URL path contains '{$keyword}' which is associated with {$brand['name']} — verify the domain carefully"
                    );
                }
            }
        }

        // No brand match found at all
        return $this->noMatchResult($domain);
    }

    // ─── Result Builders ──────────────────────────────────────────────

    private function safeResult(string $brandName, string $domain): array
    {
        return [
            'status'           => 'success',
            'is_impersonating' => false,
            'matched_brand'    => $brandName,
            'submitted_domain' => $domain,
            'technique'        => null,
            'risk_score'       => 0,
            'verdict'          => 'safe',
            'summary'          => "'{$domain}' is the verified official domain of {$brandName}",
        ];
    }

    private function impersonationResult(
        array  $brand,
        string $domain,
        string $technique,
        int    $score,
        string $message
    ): array {
        return [
            'status'            => 'success',
            'is_impersonating'  => true,
            'matched_brand'     => $brand['name'],
            'official_domains'  => $brand['official'],
            'submitted_domain'  => $domain,
            'technique'         => $technique,
            'risk_score'        => $score,
            'verdict'           => $score >= 30 ? 'malicious' : 'suspicious',
            'summary'           => $message,
        ];
    }

    private function noMatchResult(string $domain): array
    {
        return [
            'status'           => 'success',
            'is_impersonating' => false,
            'matched_brand'    => null,
            'submitted_domain' => $domain,
            'technique'        => null,
            'risk_score'       => 0,
            'verdict'          => 'safe',
            'summary'          => 'No known brand impersonation detected',
        ];
    }
}