---------------Step 1: Install Laravel Sanctum & Firebase JWT
We need two key packages:

Laravel Sanctum: For generating secure API tokens (JWT-like).
Firebase JWT: To verify Google’s ID tokens.

1. Run these commands in your terminal:
(Make sure you’re in your project folder: google-auth-api)

composer require laravel/sanctum firebase/php-jwt
php artisan vendor:publish --provider="Laravel\Sanctum\SanctumServiceProvider"
php artisan migrate

What this does:
laravel/sanctum: Adds token-based authentication to Laravel.
firebase/php-jwt: Validates Google’s ID tokens.
migrate: Creates database tables for users and tokens.

2. Verify Sanctum is installed:
Check config/sanctum.php exists.

-------------------Step 2: Configure Sanctum
Sanctum needs slight tweaking to work with APIs.

1. Update config/sanctum.php:
Change the stateful domains (for web/mobile apps):

'stateful' => explode(',', env('SANCTUM_STATEFUL_DOMAINS', 'localhost,127.0.0.1')),

2. Add to .env:
SANCTUM_STATEFUL_DOMAINS=localhost,127.0.0.1
SESSION_DOMAIN=localhost

(This allows tokens to work on your local dev server.)

---------------------------Step 3: Create the Google Auth Endpoint
Now, let’s build the /auth/google API.

1. Generate a Controller:
php artisan make:controller Auth/GoogleAuthController

2. Paste this code into app/Http/Controllers/Auth/GoogleAuthController.php:
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Str;

class GoogleAuthController extends Controller
{
    public function handleGoogleAuth(Request $request)
    {
        // 1. Validate the Google ID token exists
        $request->validate([
            'google_id_token' => 'required|string',
        ]);

        // 2. Verify the Google token
        try {
            $googleUser = $this->verifyGoogleToken($request->google_id_token);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Invalid Google token'], 401);
        }

        // 3. Find or create the user
        $user = User::firstOrCreate(
            ['email' => $googleUser->email],
            [
                'name' => $googleUser->name,
                'password' => Str::random(32), // Dummy password (not used)
                'google_id' => $googleUser->sub,
            ]
        );

        // 4. Generate tokens
        $accessToken = $user->createToken('google-access-token')->plainTextToken;
        $refreshToken = $user->createToken('google-refresh-token')->plainTextToken;

        // 5. Return response
        return response()->json([
            'status' => $user->wasRecentlyCreated ? 'new_user' : 'existing_user',
            'message' => $user->wasRecentlyCreated 
                ? 'Google verified. Complete registration.' 
                : 'Login successful',
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
        ]);
    }

    private function verifyGoogleToken($idToken)
    {
        $client = new \Google_Client(['client_id' => env('GOOGLE_CLIENT_ID')]);
        return $client->verifyIdToken($idToken);
    }
}
   
3. Add the route in routes/api.php:
Since Laravel 11 streamlined the structure, here’s how to proceed:

3.1 Create routes/api.php Manually
Navigate to your project’s routes/ folder. Create a new file named api.php. Paste this boilerplate code:

<?php

use Illuminate\Support\Facades\Route;

Route::prefix('api')->group(function () {
    // Your API routes will go here
});

3.2 Register the API Routes
Open bootstrap/app.php.

Add this line before the ->withRouting() call:

->withRouting(
    api: __DIR__.'/../routes/api.php', // Add this line
    web: __DIR__.'/../routes/web.php'
)

3.3 Add Your Google Auth Route. Now edit routes/api.php:

use App\Http\Controllers\Auth\GoogleAuthController;

Route::post('/auth/google', [GoogleAuthController::class, 'handleGoogleAuth']);

-------------------Step 4: Test Your API
1. Start the Laravel server:
php artisan serve
2. Test with Postman/Insomnia:
Method: POST
URL: http://localhost:8000/api/auth/google
Body (JSON):

json
{
  "google_id_token": "paste-a-valid-google-id-token-here"
}
(To get a test Google ID token, Follow this instruction)
--->
1. First, log in to Firebase (if you haven't):
Run this in any terminal:

firebase login

➔ Follow the browser prompt to log in with Google.
2. Create a Temporary Firebase Project (Just for Testing Tokens)

emp-firebase-test  # Create a temp folder (anywhere)
cd temp-firebase-test    # Go into it
firebase init emulators   # Initialize Firebase here

When you see this prompt:

? Which Firebase emulators do you want to set up? Press Space to select emulators, then Enter to confirm your choices.
Press SPACEBAR to select "Authentication" (you should see a ◉ appear next to it)
Then press ENTER

For the remaining questions:

"Would you like to download the emulators now?" → Type N for No
"Which port do you want to use?" → Just press ENTER for default (9099)

Now start the emulator:

firebase emulators:start

What You Should See:

i  emulators: Starting emulators: auth
✔  auth: Authentication emulator ready at http://localhost:9099

Why This Works:
You must explicitly select at least one emulator (in this case, Authentication)
The previous attempts didn't actually enable any emulators
This fresh start ensures you properly configure the authentication emulator

To Generate a Test Token:
Once the emulator is running, in a NEW terminal window run:

Here's the complete CMD-ready solution to create a test user and get a valid ID token from the Firebase Emulator:

1. First, Create the Test User:
curl -X POST "http://localhost:9099/identitytoolkit.googleapis.com/v1/accounts:signUp?key=any_key_works" -H "Content-Type: application/json" -d "{\"email\":\"test@example.com\",\"password\":\"password\",\"returnSecureToken\":true}"
2. Then Sign In to Get the Token:
curl -X POST "http://localhost:9099/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=any_key_works" -H "Content-Type: application/json" -d "{\"email\":\"test@example.com\",\"password\":\"password\",\"returnSecureToken\":true}"

Copy the idToken from the response to use in your Laravel API tests.
Paste the idToken into your API request (Insomnia/Postman) to test:

{
  "google_id_token": "PASTE_THE_TOKEN_HERE"
}


Expected Responses:
New User:

json
{
  "status": "new_user",
  "message": "Google verified. Complete registration.",
  "access_token": "xxx",
  "refresh_token": "yyy"
}
Existing User:

json
{
  "status": "existing_user",
  "message": "Login successful",
  "access_token": "xxx",
  "refresh_token": "yyy"
}
