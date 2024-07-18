<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;

use App\Models\User;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $request->validate([
            'name' => ['required', 'max:255'],
            'email' => ['required', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'confirmed', 'min:8'],
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        $device = substr($request->userAgent() ?? '', 0, 255);
        return response()->json(['access_token' => $user->createToken($device)->plainTextToken], Response::HTTP_CREATED);
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required'],
        ]);

        if (!Auth::attempt($credentials)) {
            return response()->json(null, Response::HTTP_UNAUTHORIZED);
        }

        $user = auth()->user();
        $user->tokens()->delete();
        $device = substr($request->userAgent() ?? '', 0, 255);
        return response()->json([
            'user' => $user,
            'access_token' => $user->createToken($device)->plainTextToken
        ], Response::HTTP_OK);
    }
}
