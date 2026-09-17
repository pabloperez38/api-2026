<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\CategoriaController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/* Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum'); */

//Rutas para categorías
Route::get('/categorias', [CategoriaController::class, 'index']);
Route::post('/categorias', [CategoriaController::class, 'store'])->middleware('auth:sanctum');
Route::get('/categorias/{id}', [CategoriaController::class, 'show'])->middleware('auth:sanctum');
Route::put('/categorias/{id}', [CategoriaController::class, 'update'])->middleware('auth:sanctum');
Route::delete('/categorias/{id}', [CategoriaController::class, 'destroy'])->middleware('auth:sanctum');
Route::put('/categorias/{id}/restore', [CategoriaController::class, 'restore'])->middleware('auth:sanctum');

//Login
Route::post('/login', [AuthController::class, 'login']);
Route::post('/register', [AuthController::class, 'register']);
