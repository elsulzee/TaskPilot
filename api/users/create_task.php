<?php
require_once "../config/bootstrap.php";

header("Content-Type: application/json");

// Only accept POST method
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

// Validate user ID from database
$user_check = $conn->prepare("SELECT id FROM users WHERE id = ?");
$user_check->bind_param("i", $user_id);
$user_check->execute();
$user_result = $user_check->get_result();
$user_check->close();

if ($user_result->num_rows === 0) {
    respond(false, "Invalid user or token inserted.");
}

// Sanitize inputs
$title = isset($_POST['title']) ? trim(clean_input($_POST['title'])) : null;
$description = isset($_POST['description']) ? trim(clean_input($_POST['description'])) : null;
$due_date = isset($_POST['due_date']) ? trim(clean_input($_POST['due_date'])) : null;

// Validate required fields
if (empty($title) || empty($description)) {
    respond(false, "Title and description are required.");
}

//  Validate due_date format (YYYY-MM-DD)
if ($due_date && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $due_date)) {
    respond(false, "Due date must be in YYYY-MM-DD format.");
}

// Default status
$task_status = 'pending';

// Insert task
$stmt = $conn->prepare("INSERT INTO tasks (user_id, title, description, task_status, due_date) VALUES (?, ?, ?, ?, ?)");
$stmt->bind_param("issss", $user_id, $title, $description, $task_status, $due_date);

if ($stmt->execute()) {
    respond(true, "Task created successfully.");
} else {
    respond(false, "Failed to create task.");
}

$stmt->close();
$conn->close();
?>
