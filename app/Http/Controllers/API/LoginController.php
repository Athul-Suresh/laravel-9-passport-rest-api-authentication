<?php

namespace App\Http\Controllers\API;


use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Auth;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;
use App\Models\User;
use Illuminate\Validation\Rules;
class LoginController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required',
            'password' => 'required',
        ]);
        if (auth()->attempt($request->all())) {
            $user= Auth::user();
            return response([
                'user' => $user,
                '_token' => $user->createToken('_token')->accessToken
            ], Response::HTTP_OK);
        }

        return response([
            'message' => 'Invalid credentials or User does not exist'
        ], Response::HTTP_UNAUTHORIZED);
    }

    public function register(Request $request)
    {
        
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
        ]);
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        return response($user, Response::HTTP_CREATED);
    }
    public function logout()
    {
        //   $request->user()->token()->revoke();
        Auth::guard('api')->user()->tokens->each(function ($token, $key) {
            $token->delete();
        });
        return response()->json([
            'status' => 'success',
            'message' => 'successful-logout']);
    }
}
