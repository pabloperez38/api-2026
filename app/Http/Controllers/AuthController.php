<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;
use Throwable;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        try {
            // Validar datos de entrada
            $validated = $request->validate(
                [
                    'email' => [
                        'required',
                        'string',
                        'email',
                        'max:255',
                    ],

                    'password' => [
                        'required',
                        'string',
                    ],
                ],
                [
                    'email.required' => 'El campo correo electrónico es obligatorio.',
                    'email.string' => 'El correo electrónico debe ser texto.',
                    'email.email' => 'El campo correo electrónico debe ser una dirección de correo válida.',
                    'email.max' => 'El correo electrónico no puede superar los 255 caracteres.',

                    'password.required' => 'El campo contraseña es obligatorio.',
                    'password.string' => 'La contraseña debe ser texto.',
                ]
            );

            // Buscar usuario
            $user = User::where('email', $validated['email'])->first();

            // Verificar credenciales
            if (
                !$user ||
                !Hash::check($validated['password'], $user->password)
            ) {
                return response()->json([
                    'success' => false,
                    'message' => 'Las credenciales proporcionadas son incorrectas.',                  
                ], 401);
            }

            // Generar token Sanctum
            $token = $user->createToken('auth_token')->plainTextToken;

            // Respuesta exitosa
            return response()->json([
                'success' => true,
                'message' => 'Login exitoso.',
                'data' => [
                    'access_token' => $token,
                    'token_type' => 'Bearer',
                    'user' => $user,
                ],
            ], 200);
        } catch (ValidationException $e) {

            // Error de validación
            return response()->json([
                'success' => false,
                'message' => 'Los datos proporcionados no son válidos.',
                'errors' => $e->errors(),
            ], 422);
        } catch (QueryException $e) {

            // Error de base de datos
            Log::error('Error de base de datos durante el login', [
                'message' => $e->getMessage(),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'No se pudo completar el inicio de sesión.',
                'error' => 'database_error',
            ], 500);
        } catch (Throwable $e) {

            // Error inesperado
            Log::error('Error inesperado durante el login', [
                'message' => $e->getMessage(),               
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Ocurrió un error inesperado.',
                'error' => 'internal_server_error',
            ], 500);
        }
    }

    public function register(Request $request)
    {
        try {
            // Validar los datos recibidos
            $validated = $request->validate([
                'name' => [
                    'required',
                    'string',
                    'max:255',
                ],

                'email' => [
                    'required',
                    'string',
                    'email',
                    'max:255',
                    'unique:users,email',
                ],

                'password' => [
                    'required',
                    'string',
                    'min:6',
                ],

                'role_id' => [
                    'required',
                    'integer',
                    'exists:roles,id',
                ],
            ], [
                'name.required' => 'El campo nombre es obligatorio.',
                'name.string' => 'El nombre debe ser texto.',
                'name.max' => 'El nombre no puede superar los 255 caracteres.',

                'email.required' => 'El campo correo electrónico es obligatorio.',
                'email.string' => 'El correo electrónico debe ser texto.',
                'email.email' => 'El correo electrónico no es válido.',
                'email.max' => 'El correo electrónico no puede superar los 255 caracteres.',
                'email.unique' => 'El correo electrónico ya está registrado.',

                'password.required' => 'El campo contraseña es obligatorio.',
                'password.string' => 'La contraseña debe ser texto.',
                'password.min' => 'La contraseña debe tener al menos 6 caracteres.',

                'role_id.required' => 'El campo rol es obligatorio.',
                'role_id.integer' => 'El rol debe ser un número entero.',
                'role_id.exists' => 'El rol seleccionado no existe.',
            ]);

            // Crear usuario dentro de una transacción
            $user = DB::transaction(function () use ($validated) {
                return User::create([
                    'name' => $validated['name'],
                    'email' => $validated['email'],
                    'password' => Hash::make($validated['password']),
                    'role_id' => $validated['role_id'],
                ]);
            });

            // Generar token de Sanctum
            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json([
                'success' => true,
                'message' => 'Usuario registrado correctamente.',
                'data' => [
                    'access_token' => $token,
                    'token_type' => 'Bearer',
                    'user' => $user,
                ],
            ], 201);
        } catch (ValidationException $e) {

            // Error de validación
            return response()->json([
                'success' => false,
                'message' => 'Los datos proporcionados no son válidos.',
                'errors' => $e->errors(),
            ], 422);
        } catch (QueryException $e) {

            // Error relacionado con la base de datos
            return response()->json([
                'success' => false,
                'message' => 'No se pudo completar el registro.',
                'error' => 'database_error',
            ], 500);
        } catch (Throwable $e) {

            // Cualquier otro error inesperado
            return response()->json([
                'success' => false,
                'message' => 'Ocurrió un error inesperado.',
                'error' => 'internal_server_error',
            ], 500);
        }
    }
}
