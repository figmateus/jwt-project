<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use JWTAuth;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
//    public function __construct()
//    {
//        $this->middleware('auth:api', ['except' => ['login']]);
//    }

    public function register(Request $request)
    {
        return User::create([
            'name' => $request->input('name'),
            'email' => $request->input('email'),
            'password' => Hash::make($request->input('password')),
        ]);
    }

    public function user()
    {
        try {
            if(!auth()->user()){
                return [
                    'success' => false,
                    'message' => 'User not Logged',
                    'data' => [],
                    'http_code' => Response::HTTP_NOT_FOUND
                ];
            }
        }catch (JWTException $e){
            return [
                'success' => false,
                'message' => 'User not Logged',
                'data' => [],
                'http_code' => Response::HTTP_BAD_REQUEST
            ];
        }

        return [
            'success' => true,
            'message' => 'User Logged',
            'data' => [auth()->user()],
            'http_code' => Response::HTTP_OK
        ];
    }

    public function login(Request $request)
    {
        try {
            if(! $token = JWTAuth::attempt($request->only('email', 'password'))) {
                return [
                    'success' => false,
                    'message' => 'Login credentials are invalid',
                    'data' => [],
                    'http_code' => Response::HTTP_BAD_REQUEST
                ];
            }
        } catch (JWTException $e){
            return [
                'success' => false,
                'message' => 'Could not create token',
                'data' => [],
                'http_code' => Response::HTTP_SERVICE_UNAVAILABLE
            ];
        }

        return [
            'success' => true,
            'message' => 'Token created successfully',
            'data' => [
                'token' => $token
            ],
            'http_code' => Response::HTTP_OK
        ];
    }

    public function logout(Request $request)
    {
        try {
            JWTAuth::invalidate($request->token);

            return response()->json([
                'message' => 'User has been logged out'
            ],201);
        } catch(JWTException $e) {

//            dd($e->getMessage());
            return response()->json([
                'message' => 'Sorry, user cannot be logged out'
            ],503);
        }
    }

    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }

}
