<?php
require_once "../config/bootstrap.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

header("Content-Type/ application/json");

// Authorization header check

$header = apache_request_headers();
$authHeader = $header["Authorization"] ?? '';
$token = trim(str_replace("Bearer", '', $authHeader));

if (empty($token)){
    respond(false, "Unauthorized: token is missing.");
}

try {
//   Decode the JWT token
$decoded = validate_jwt($token);

if (!$decoded || $decoded['role'] !== 'admin') {
    respond(false, "Unauthorized access: Admin only.");
}

$admin_id = $decoded['id'];

// Validate admin ID from database
$admin_check = $conn->prepare("SELECT id FROM admins WHERE id = ?");
$admin_check->bind_param("i", $admin_id);
$admin_check->execute();
$admin_result = $admin_check->get_result();

if ($admin_result->num_rows === 0) {
   respond(false, " Invalid admin or token inserted");
}


    // All good, welcome admin!
    respond(true, "Welcome to Admin dashboard", [
        "admin" => [
            "admin_id" => $decoded['admin_id'],
            "email" => $decoded['email'],
            "role" => $decoded['role']
        ]
    ]);

} catch (Exception $e) {
    respond(false, "Invalid or expired token");
}
