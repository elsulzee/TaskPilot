<?php
require_once "../config/bootstrap.php";

header("Content-Type: application/json");

$token = isset($_GET['token']) ? clean_input(trim($_GET['token'])) : null;


if (!$token) {
    respond(false, "Verification token is required.");
}

// Check token
$stmt = $conn->prepare("SELECT id FROM users WHERE verify_token = ?");
$stmt->bind_param("s", $token);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows !== 1) {
    respond(false, "Invalid or expired verification token.");
}

$user = $result->fetch_assoc();

// Update email_verified
$update = $conn->prepare("UPDATE users SET email_verified = 1, verify_token = NULL WHERE id = ?");
$update->bind_param("i", $user['id']);
$update->execute();
if ($update->execute()){
respond(true, "Email verified successfully. You can now log in.");
} else {
    http_response_code(500);
    respond(false, "Failed to update verification status.");
}
?>
