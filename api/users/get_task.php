<?php
require_once "../config/bootstrap.php";

header("Content-Type: application/json");

// Allow only GET method
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
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
    respond(false, "Invalid user or token Inserted.");
}

// Get and validate task_id
if (!isset($_GET['task_id']) || !is_numeric($_GET['task_id'])) {
    respond(false, "Task ID is required and must be numeric.");
}

$task_id =isset($_GET["task_id"]) ? clean_input($_GET['task_id']) : 0;

// Fetch task only if it belongs to the logged-in user
$stmt = $conn->prepare("SELECT * FROM tasks WHERE id = ? AND user_id = ?");
$stmt->bind_param("ii", $task_id, $user_id);
$stmt->execute();
$result = $stmt->get_result();
$task = $result->fetch_assoc();
$stmt->close();

if ($task) {
    respond(true, "Task fetched successfully.", ["task" => $task]);
} else {
    respond(false, "Task not found or access denied.");
}

$conn->close();
?>
