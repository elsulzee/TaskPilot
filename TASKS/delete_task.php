<?php
require_once "../CONFIG/task_pilot_db.php"; // Include DB connection
require_once "../JWT/jwt_handler.php"; // Include JWT handler for verifying token

header("Content-Type: application/json");

// Check for DELETE method
if ($_SERVER['REQUEST_METHOD'] !== 'DELETE') {
    echo json_encode(["error" => "Invalid request method."]);
    exit;
}

// Retrieve JWT token from headers
$headers = getallheaders();
if (!isset($headers['Authorization'])) {
    echo json_encode(["error" => "Authorization token required."]);
    exit;
}


$authHeader = $headers['Authorization'];
$token = str_replace("Bearer ", "", $authHeader);

// Decode JWT token to get user data
$user_data = validate_jwt($token);
if (!$user_data) {
    echo json_encode(["error" => "Invalid or expired token."]);
    exit;
}

// Get task ID
$task_id = isset($_GET['task_id']) ? clean_input($_GET['task_id']) : null;
if (empty($task_id)) {
    echo json_encode(["error" => "Task ID is required."]);
    exit;
}

// Delete the task
$stmt = $conn->prepare("DELETE FROM tasks WHERE id = ?");
$stmt->bind_param("i", $task_id);

if ($stmt->execute()) {
    echo json_encode(["message" => "Task deleted successfully."]);
} else {
    echo json_encode(["error" => "Failed to delete task."]);
}

$stmt->close();
$conn->close();
?>
