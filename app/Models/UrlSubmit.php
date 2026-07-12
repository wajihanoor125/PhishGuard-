<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class UrlSubmit extends Model
{
    protected $fillable = [
    'url',
    'url_hash',
    'domain',
    'risk_score',
    'verdict',
    'virustotal_result',
    'google_sb_result',
    'domain_age_result',
    'pattern_result',               
    'brand_impersonation_result',
    'ip_address',
    'share_token',
];
protected $casts = [
    'virustotal_result'          => 'array',
    'google_sb_result'           => 'array',
    'domain_age_result'          => 'array',
    'pattern_result'             => 'array', 
    'brand_impersonation_result' => 'array',
];
}
