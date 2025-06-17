<?php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Dotenv\Dotenv;

require_once __DIR__ . '/../vendor/autoload.php';
// ✅ Correct path: go up one level from JWT to TaskPilot
$dotenv = Dotenv::createImmutable(__DIR__ . "/..");
$dotenv->load();
$dotenv = Dotenv::createImmutable(__DIR__ . "/..");
$dotenv->load();
$secret_key = $_ENV["SECRET_KEY"];

function generate_jwt($payload) {
    global $secret_key;

    $issuedAt = time();
    $expire = $issuedAt + (60 * 60 * 24);

    $token = [
        "iss" => "http://localhost",
        "aud" => "http://localhost",
        "iat" => $issuedAt,
        "exp" => $expire,
        "data" => $payload
    ];

    return JWT::encode($token, $secret_key, 'HS256');
}

function validate_jwt($jwt) {
    global $secret_key;

    try {
        $decoded = JWT::decode($jwt, new Key($secret_key, 'HS256'));
        return $decoded->data;
    } catch (Exception $e) {
        return null;
    }
}
