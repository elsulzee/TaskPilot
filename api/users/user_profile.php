<?php
require_once "../config/bootstrap.php";

header("Content-Type: application/json");

// Get Authorization header
$header = apache_request_headers();
$authHeader = $header["Authorization"] ?? '';
$token = trim(str_replace("Bearer", '', $authHeader));

if (empty($token)) {
    respond(false, "Unauthorized: token is missing.");
}

// Decode JWT token
$user_data = validate_jwt($token);
if (!$user_data || !isset($user_data->id)) {
    respond(false, "Invalid or expired token.");
}

$user_id = $user_data->id;

// Validate user ID exists in database
$user_check = $conn->prepare("SELECT id FROM users WHERE id = ?");
$user_check->bind_param("i", $user_id);
$user_check->execute();
$user_result = $user_check->get_result();
$user_check->close();

if ($user_result->num_rows === 0) {
    respond(false, "Invalid user or token.");
}

// Fetch user profile by ID
$stmt = $conn->prepare("SELECT id, name, email, created_at FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 1) {
    $user = $result->fetch_assoc();

    respond(true,  "Profile fetched successfully",["User" => $user]);
} else {
   respond(false, "User not found.");
}

$stmt->close();
$conn->close();
?>
