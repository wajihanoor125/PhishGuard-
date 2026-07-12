<?php

use Illuminate\Support\Facades\Route;
use  App\Http\Controllers\UrlSubmitController;

Route::get('/', function () {
    return view('User.index');
})->name('index');
// pdf report
Route::get('/report/{id}', [UrlSubmitController::class, 'downloadReport'])->name('report.download');