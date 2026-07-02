<?php

use Illuminate\Http\Request;
use App\Http\Controllers\UrlSubmitController;
use Illuminate\Support\Facades\Route;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

// Scan URL Route
Route::post('/url',[UrlSubmitController::class,'scan'])->name('urlscan');