<?php

namespace App\Http\Controllers;

use App\Services\AuthService;
use Illuminate\Http\Request;
use MongoDB\Exception\InvalidArgumentException;
use Tymon\JWTAuth\Exceptions\JWTException;
use JWTAuth;

class AuthController extends Controller
{
    private $authService;

    public function __construct(AuthService $authService)
    {
        $this->authService = $authService;
    }

    public function register(Request $request)
    {
        $data = $request->only('name', 'email', 'password');

        try {
		    $user = $this->authService->create($data);
		    return response()->json([
                'status'    => 201,
                'data'      => $user,
            ]);
        } catch (\Throwable $e) {
            if ($e instanceof InvalidArgumentException) {
                // Check if the exception is indeed an InvalidArgumentException
                return response()->json([
                    'status' => 422,
                    'error' => $e->getMessage(), // Access the message property
                ]);
            }
        // catch (InvalidArgumentException $e) {
        // //     return response()->json([
        // //         'status'    => 422,
        // //         'error'     => $e->getMessage(),
        // //     ]);
        }
    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        try {
            if (!$token = $this->authService->authenticate($credentials)) {
                return response()->json([
                    'status'    => 401,
                    'error'     => 'Invalid credentials.',
                ], 401);
            }
            else {
                return response()->json([
                    'access_token' => $token,
                    'token_type' => 'bearer',
                    'expires_in' => auth()->factory()->getTTL() * 60,
                ]);
            }
        } catch (InvalidArgumentException $e) {
            return response()->json([
                'status'    => 422,
                'error'     => $e->getMessage(),
            ]);
        } catch (JWTException $e) {
            return response()->json([
                'status'    => 500,
                'error'     => 'Could not create token.',
            ], 500);
        }
    }

    public function logout()
    {
        $this->authService->logout();
        return response()->json([
            'status'    => 200,
            'message' => 'Successfuly logged out'
        ], 200);
    }
}
