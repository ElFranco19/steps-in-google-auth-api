# steps-in-google-auth-api

You're welcome! Let's begin with the **first step**: **Setting Up Firebase**.

### **Step 1: Set Up Firebase**

1. **Create a Firebase Project:**

   - Go to the [Firebase Console](https://console.firebase.google.com/).
   - Click on **"Add Project"**.
   - Enter a name for your project (e.g., **google-auth-api**) and click **"Continue"**.
   - You can skip the Google Analytics setup if you don't need it for now, then click **"Create Project"**.

2. **Enable Google Sign-In for Firebase Authentication:**

   - In the Firebase Console, go to your newly created project.
   - In the left-hand menu, click on **Authentication**.
   - Under the **Sign-in method** tab, you'll see a list of authentication providers. Click **Google** and toggle it to **Enable**.
   - Click **Save**.

3. **Generate Firebase Admin SDK Private Key:**

   To interact with Firebase from the backend, you'll need a **private key** for the Firebase Admin SDK.

   - In the Firebase Console, click on the **gear icon** in the top left and go to **Project Settings**.
   - In the **Service accounts** tab, click on **Generate new private key**. This will download a JSON file containing the credentials needed to authenticate with Firebase.

4. **Store the Firebase Admin SDK Key in Your Laravel Project:**

   - Move the downloaded JSON file to a safe location in your Laravel project. A good place to store it is in the `storage` folder.
   - You can create a subfolder like `storage/app/firebase/` and place the file there. Let’s assume the file is named `serviceAccountKey.json`.

Once you’ve completed these steps, let me know, and we’ll move on to the next part of the process!

______________________________________________________________________________________________________________________________________________________________________________


Great job! Now that Firebase is set up, let's move on to **Step 2**: **Set Up Firebase in Your Laravel Project**.

### **Step 2: Set Up Firebase in Laravel**

#### 1. **Install the Firebase SDK for PHP**

We need to install the **kreait/firebase-php** package to interact with Firebase in our Laravel backend.

- In your terminal, run the following command inside your Laravel project folder:

```bash
composer require kreait/firebase-php
```

This will install the necessary package for Firebase integration.

#### 2. **Create Firebase Configuration File**

We need to create a configuration file in Laravel to store the path to the Firebase Admin SDK key and any necessary configurations.

- In your Laravel project, create a new configuration file. Run this command in the terminal:

```bash
touch config/firebase.php
```

- Open the `config/firebase.php` file and add the following code to load your Firebase credentials:

```php
<?php

return [
    'credentials' => storage_path('app/firebase/serviceAccountKey.json'), // Path to your service account key file
];
```

Make sure the path points to where you stored the **`serviceAccountKey.json`** file inside the `storage` folder.

#### 3. **Create Firebase Authentication Service**

Now let’s create a service to interact with Firebase Authentication. This will allow us to verify the Google ID Token sent by the mobile client.

- Run the following command to create a service class:

```bash
php artisan make:service FirebaseAuthService
```

- Open the newly created file at `app/Services/FirebaseAuthService.php` and add the following code:

```php
namespace App\Services;

use Kreait\Firebase\Factory;
use Kreait\Firebase\Auth;

class FirebaseAuthService
{
    protected $auth;

    public function __construct()
    {
        $this->auth = (new Factory)
                        ->withServiceAccount(config('firebase.credentials'))  // Load credentials from config
                        ->createAuth();
    }

    public function verifyGoogleIdToken($idToken)
    {
        try {
            $verifiedIdToken = $this->auth->verifyIdToken($idToken);
            return $verifiedIdToken;
        } catch (\Exception $e) {
            throw new \Exception('Invalid ID token: ' . $e->getMessage());
        }
    }
}
```

This service will handle verifying the Google ID Token using Firebase.

#### 4. **Test the Firebase Integration**

At this point, you’ve set up Firebase integration in your Laravel project. The next step will be to create the route and controller for handling the `/auth/google` endpoint, but before that, let’s confirm that everything is working.

To verify, try calling the `verifyGoogleIdToken()` method from FirebaseAuthService and pass a test Google ID Token (which we will obtain from the frontend later).

You can test this service in your **Tinker** shell by running:

```bash
php artisan tinker
```

Then, you can try verifying a token:

```php
$firebaseAuthService = new \App\Services\FirebaseAuthService();
$verifiedToken = $firebaseAuthService->verifyGoogleIdToken('your-google-id-token-here');
```

If it returns a valid response, you’ve successfully integrated Firebase with your Laravel backend!

---

Once you’ve completed these steps, let me know and we’ll move on to creating the `/auth/google` route and handling the user logic (new/existing users).

_____________________________________________________________________________________________________________________________________________________________________________

