<?php
header("Content-Type: application/json");
require_once("../CONFIG/task_pilot_db.php");

$token = isset($_GET['token']) ? clean_input(trim($_GET['token'])) : null;


if (!$token) {
    echo json_encode(["error" => "Verification token is required."]);
    exit;
}

// Check token
$stmt = $conn->prepare("SELECT id FROM users WHERE verify_token = ?");
$stmt->bind_param("s", $token);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows !== 1) {
    echo json_encode(["error" => "Invalid or expired verification token."]);
    exit;
}

$user = $result->fetch_assoc();

// Update email_verified
$update = $conn->prepare("UPDATE users SET email_verified = 1, verify_token = NULL WHERE id = ?");
$update->bind_param("i", $user['id']);
$update->execute();

echo json_encode(["message" => "Email verified successfully. You can now log in."]);
?>
