<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('url_submits', function (Blueprint $table) {
           $table->id();
    $table->text('url');
    $table->string('url_hash', 64)->index();
    $table->string('domain')->nullable();

    // One column per check — clean and dedicated
    $table->json('virustotal_result')->nullable();
    $table->json('google_sb_result')->nullable();
    $table->json('domain_age_result')->nullable();
    $table->json('brand_impersonation_result')->nullable();

    // Aggregated output
    $table->integer('risk_score')->default(0);
    $table->enum('verdict', ['safe', 'caution', 'suspicious', 'malicious']);

    // Utility columns
    $table->string('ip_address', 45)->nullable();
    $table->string('share_token', 32)->unique()->nullable();
    $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('url_submits');
    }
};
