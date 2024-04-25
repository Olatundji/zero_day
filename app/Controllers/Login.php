<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use CodeIgniter\API\ResponseTrait;
use App\Models\UserModel;
use \Firebase\JWT\JWT;

class Login extends BaseController
{
    use ResponseTrait;
     
    public function index()
    {
        $userModel = new UserModel();

        $email = $this->request->getVar('email');
        $password = $this->request->getVar('password');
        $rules = [
            'email' => 'required|valid_email',
            'password' => 'required|min_length[8]',
        ];

        // Valider les entrées
        if (!$this->validate($rules)) {
            // Récupérer les erreurs de validation
            $errors = $this->validator->getErrors();
            
            // Renvoyer une réponse avec les erreurs de validation et le code HTTP 400
            return $this->fail($errors, 400);
        }
        
        try {
            $user = $userModel->where('email', $email)->first();

            if (is_null($user) || !password_verify($password, $user['password'])) {
                // Utilisateur non trouvé ou mot de passe incorrect
                return $this->respond(['error' => 'Invalid email or password.'], 401);
            }

            // Génération du token JWT
            $key = getenv('JWT_SECRET');
            $iat = time(); // timestamp actuel
            $exp = $iat + 3600; // expiration dans 1 heure

            $payload = [
                "iss" => "Issuer of the JWT",
                "aud" => "Audience that the JWT",
                "sub" => "Subject of the JWT",
                "iat" => $iat, // temps où le JWT a été émis
                "exp" => $exp, // heure d'expiration du token
                "email" => $user['email'],
            ];

            $token = JWT::encode($payload, $key, 'HS256');

            // Structure de la réponse
            $response = [
                'message' => 'Login Successful',
                'token' => $token
            ];

            // Renvoyer la réponse avec le code HTTP 200
            return $this->respond($response, 200);
        } catch (\Exception $e) {
            // Gérer les erreurs ici
            return $this->fail($e->getMessage(), 500);
        }
    }
}
