<?php
require_once "../config/bootstrap.php";

header("Content-Type: application/json");

// Ensure PUT method
if ($_SERVER['REQUEST_METHOD'] !== 'PUT') {
   respond(false, "Invalid request method.");
}

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

// Read and decode JSON input
$rawData = file_get_contents("php://input");
$putData = json_decode($rawData, true);

// Get and sanitize values
$task_id = isset($_GET['task_id']) ? clean_input($_GET['task_id']) : 0;
$task_status = isset($putData['task_status']) ? clean_input($putData['task_status']) : null;

// Validate input
$valid_statuses = ['pending', 'in_progress', 'completed'];
if (empty($task_id) || !in_array($task_status, $valid_statuses)) {
    respond(false, "Valid task ID and task status are required.");
}
//Check if task exists
$task_check = $conn->prepare("SELECT id FROM tasks WHERE id = ?");
$task_check->bind_param("i", $task_id);
$task_check->execute();
$task_result = $task_check->get_result();
if ($task_result->num_rows !== 1) {
    respond(false, "Task not found.");
}

// Proceed with update
$update = $conn->prepare("UPDATE tasks SET task_status = ? WHERE id = ?");
$update->bind_param("si", $task_status, $task_id);

if ($update->execute()) {
    respond(true, "Task status updated successfully.");
} else {
    respond(false, "Failed to update task status.");
}

// Clean up
$stmt->close();
$task_check->close();
$update->close();
$conn->close();
?>
