<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\LoginController;
/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::post('/v1/login', [LoginController::class, 'login']);
Route::post('/v1/register', [LoginController::class, 'register']);

Route::middleware('auth:api')->get('/v1/user', function (Request $request) {
    return $request->user();
});