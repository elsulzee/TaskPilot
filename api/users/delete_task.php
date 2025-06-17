<?php
require_once "../config/bootstrap.php";

header("Content-Type: application/json");

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(false, "Invalid request method.");
}

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

// Get and sanitize task ID
$task_id = isset($_POST['task_id']) ? clean_input($_POST['task_id']) : 0;
if ($task_id <= 0) {
    respond(false, "Invalid task ID.");
}

// Check if task exists and belongs to the user
$check_task = $conn->prepare("SELECT id FROM tasks WHERE id = ? AND user_id = ?");
$check_task->bind_param("ii", $task_id, $user_id);
$check_task->execute();
$task_result = $check_task->get_result();
$check_task->close();

if ($task_result->num_rows === 0) {
    respond(false, "Task not found or access denied.");
}

// Delete the task
$delete = $conn->prepare("DELETE FROM tasks WHERE id = ? AND user_id = ?");
$delete->bind_param("ii", $task_id, $user_id);

if ($delete->execute()) {
    respond(true, "Task deleted successfully.");
} else {
    respond(false, "Failed to delete task.");
}

$delete->close();
$conn->close();
?>
