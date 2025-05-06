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
----->
Create an HTML file with this code:
<!DOCTYPE html>
<html>
<head>
  <title>Firebase Google Sign-In</title>
  <script src="https://www.gstatic.com/firebasejs/10.7.1/firebase-app-compat.js"></script>
  <script src="https://www.gstatic.com/firebasejs/10.7.1/firebase-auth-compat.js"></script>
</head>
<body>
  <h1>Get Google ID Token</h1>
  <button id="signInButton">Sign in with Google</button>
  <div id="tokenInfo" style="margin-top: 20px; word-break: break-all;"></div>

  <script>
    // Your Firebase config
    const firebaseConfig = {
      apiKey: "YOUR_API_KEY",
      authDomain: "YOUR_PROJECT_ID.firebaseapp.com",
      projectId: "YOUR_PROJECT_ID",
      storageBucket: "YOUR_PROJECT_ID.appspot.com",
      messagingSenderId: "YOUR_SENDER_ID",
      appId: "YOUR_APP_ID"
    };

    // Initialize Firebase
    const app = firebase.initializeApp(firebaseConfig);
    const auth = firebase.auth();

    // Google Sign-In
    document.getElementById('signInButton').addEventListener('click', () => {
      const provider = new firebase.auth.GoogleAuthProvider();
      auth.signInWithPopup(provider)
        .then((result) => {
          // Get the ID token
          return result.user.getIdToken();
        })
        .then((idToken) => {
          console.log("ID Token:", idToken);
          
          // Display the token
          document.getElementById('tokenInfo').innerHTML = `
            <h3>ID Token:</h3>
            <textarea rows="10" cols="80">${idToken}</textarea>
            <h3>Decoded:</h3>
            <pre>${JSON.stringify(parseJwt(idToken), null, 2)}</pre>
          `;
        })
        .catch((error) => {
          console.error("Error:", error);
        });
    });

    function parseJwt(token) {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(atob(base64));
    }
  </script>
</body>
</html>

How to Get Firebase Configuration for Your Web App
With Firebase Google Sign-In, you'll need to get your Firebase configuration object. Here's how to obtain it:

Step-by-Step Guide
Go to the Firebase Console:
Visit https://console.firebase.google.com/

Select your project or create a new one
Add a web app to your project:
Click on the "</>" (web) icon in the project overview page
Register your app by giving it a nickname (e.g., "Test Auth App")

Click "Register app"

Get your Firebase config:
You'll see a code snippet with your configuration that looks like this:

javascript:
const firebaseConfig = {
  apiKey: "AIzaSyABCD...",
  authDomain: "your-project-id.firebaseapp.com",
  projectId: "your-project-id",
  storageBucket: "your-project-id.appspot.com",
  messagingSenderId: "1234567890",
  appId: "1:1234567890:web:abc123def456"
};
Copy this entire configuration object

Enable Google Authentication:
In the left sidebar, go to "Authentication" → "Sign-in method"
Click on "Google" and toggle the enable switch
Select a project support email
Click "Save"

Optional: Add authorized domains:
In the Authentication settings, go to "Settings"
Under "Authorized domains", add:
localhost
Any other domains you'll be testing from

Important Notes
The apiKey is not a secret - it's safe to include in your client-side code as it's used to identify your Firebase project.

For local testing:
Make sure localhost is in your authorized domains
You can serve your HTML file using a simple server:

terminal:
python3 -m http.server 8000
Then access it at http://localhost:8000

If you're deploying to a real domain, add that domain to your authorized domains list in Firebase console.
The configuration values you get are specific to your Firebase project - don't share them publicly if your project contains sensitive data.
<------

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

-----------------------Step 5: Implement Security Measures (Laravel 11 Specific)
Since Laravel 11 has a streamlined structure, we'll configure security settings differently than older versions. Here's how to add Rate Limiting, CORS, and Input Sanitization properly.

1. Rate Limiting (Prevent API Abuse)
Laravel 11 uses a simpler middleware setup in bootstrap/app.php.

A. Configure Rate Limiting Globally
Open bootstrap/app.php and modify the withMiddleware() section:

php
->withMiddleware(function (Middleware $middleware) {
    $middleware->api([
        \Illuminate\Routing\Middleware\ThrottleRequests::class . ':60,1', // 60 requests per minute
    ]);

✅ Test it:

Send >60 requests in 1 minute to /api/auth/google.
Expected response: 429 Too Many Requests.

2. CORS (Allow Frontend to Access API)
Laravel 11 removes the default CORS package, so we'll use a middleware.

A. Create a Custom CORS Middleware
Generate middleware:

bash:
php artisan make:middleware Cors

Edit app/Http/Middleware/Cors.php:
public function handle($request, Closure $next)
{
    return $next($request)
        ->header('Access-Control-Allow-Origin', '*') // Or your frontend URL (e.g., 'http://localhost:3000')
        ->header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        ->header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

Register it in bootstrap/app.php:
php
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\App\Http\Middleware\Cors::class);
})

✅ Test it:
Call the API from a frontend app (e.g., React/Vue).
Check browser’s Network tab for CORS headers.

3. Input Sanitization (Prevent Malicious Tokens)
We’ll enhance validation in GoogleAuthController.php.

A. Strict Google ID Token Validation
Update the handleGoogleAuth method:

$request->validate([
    'google_id_token' => [
        'required',
        'string',
        function ($attribute, $value, $fail) {
            if (!preg_match('/^[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+$/', $value)) {
                $fail('The ' . $attribute . ' is invalid.');
            }
        },
    ],
]);

B. Sanitize User Data (Optional)
If storing user data, add to User::firstOrCreate():

php
$user = User::firstOrCreate(
    ['email' => filter_var($claims['email'], FILTER_SANITIZE_EMAIL)],
    [
        'name' => htmlspecialchars($claims['name'] ?? 'Google User'),
        'password' => Str::random(32),
        'google_id' => $claims['sub'],
    ]
);

✅ Test it:

Send a malformed token (e.g., "google_id_token": "<script>alert('xss')</script>").
Expected response: 422 Unprocessable Entity with an error.

4. Additional Security (Optional but Recommended)
A. HTTPS Enforcement (For Production)

In bootstrap/app.php:
php
->withMiddleware(function (Middleware $middleware) {
    $middleware->web(\Illuminate\Http\Middleware\TrustProxies::class);
    $middleware->web(\Illuminate\Http\Middleware\HandleCors::class);
    $middleware->web(\App\Http\Middleware\ForceHttps::class); // 👈 Add this
})
Create ForceHttps middleware:

bash:
php artisan make:middleware ForceHttps

Then edit it:

php
public function handle($request, Closure $next)
{
    if (!$request->secure() && app()->isProduction()) {
        return redirect()->secure($request->getRequestUri());
    }
    return $next($request);
}

B. Disable Token Database Exposure

In app/Models/User.php:
php
protected $hidden = [
    'password',
    'remember_token',
    'google_id', // 👈 Hide sensitive fields
];

✅ Final Verification
Rate Limiting:
Send 60+ requests in 1 minute → Should block with 429.
CORS:
Call API from a frontend → No CORS errors.
Input Sanitization:
Send invalid token → Returns 422 validation error.
