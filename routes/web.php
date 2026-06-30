<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('User.index');
})->name('index');
