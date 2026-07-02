<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

class NoLocalNetwork implements ValidationRule
{
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $host = parse_url($value, PHP_URL_HOST);

        if (!$host) {
            $fail('Invalid URL structure.');
            return;
        }

        // Block localhost
        if (in_array($host, ['localhost', '127.0.0.1', '::1'])) {
            $fail('Local addresses are not allowed.');
            return;
        }

        // Block private IP ranges
        $ip = gethostbyname($host);

        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                $fail('Private or reserved IP addresses are not allowed.');
            }
        }
    }
}