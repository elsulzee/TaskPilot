<?php
require_once "../config/bootstrap.php";

header("Content-Type: application/json");

// Authorization header check

$header = apache_request_headers();
$authHeader = $header["Authorization"] ?? '';
$token = trim(str_replace("Bearer", '', $authHeader));

if (empty($token)){
    respond(false, "Unauthorized: token is missing.");
}

// Decode the JWT token
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

// Get user ID to delete
$user_id = isset($_GET['user_id']) ? (int) clean_input($_GET['user_id']) : 0;
if ($user_id <= 0) {
    respond(false, "Invalid or missing user ID");
}

// Check if the user exists
$stmt = $conn->prepare("SELECT id FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$stmt->close();

if (!$user) {
    respond(false, "User not found");
}

// First, delete tasks created by the user
$delete_tasks = $conn->prepare("DELETE FROM tasks WHERE user_id = ?");
$delete_tasks->bind_param("i", $user_id);
$delete_tasks->execute();
$delete_tasks->close();

// Now delete the user
$delete_user = $conn->prepare("DELETE FROM users WHERE id = ?");
$delete_user->bind_param("i", $user_id);

if ($delete_user->execute()) {
    respond(true, "User and all related tasks deleted successfully");
} else {
    respond(false, "Failed to delete user");
}

$delete_user->close();
$conn->close();
