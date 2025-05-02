<?php
header("Content-Type: application/json");

// Include database and JWT dependencies
require_once("../CONFIG/task_pilot_db.php");
require_once("../JWT/jwt_handler.php");

// Get Authorization header
$headers = apache_request_headers();
$authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : null;

if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
    echo json_encode(["error" => "Authorization token not found."]);
    exit;
}

$jwt = $matches[1];

// Decode the token
$decoded = validate_jwt($jwt);

if (!$decoded) {
    echo json_encode(["error" => "Invalid or expired token."]);
    exit;
}

// Extract email or ID from token payload
$user_email = $decoded->email ?? null;

if (!$user_email) {
    echo json_encode(["error" => "Invalid token payload."]);
    exit;
}

// Fetch user profile
$stmt = $conn->prepare("SELECT id, name, email, created_at FROM users WHERE email = ?");
$stmt->bind_param("s", $user_email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 1) {
    $user = $result->fetch_assoc();

    echo json_encode([
        "message" => "Profile fetched successfully",
        "user" => $user
    ]);
} else {
    echo json_encode(["error" => "User not found."]);
}
?>
