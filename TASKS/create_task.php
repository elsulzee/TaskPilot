<?php
require_once "../CONFIG/task_pilot_db.php"; // Include DB connection
require_once "../JWT/jwt_handler.php"; // Include JWT handler for verifying token

header("Content-Type: application/json");

// Check for POST method
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(["error" => "Invalid request method."]);
    exit;
}

// Clean input function to sanitize user data
function clean_input($data) {
    return htmlspecialchars(strip_tags(trim($data)));
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

// Extract data from POST request
$title = isset($_POST['title']) ? clean_input($_POST['title']) : null;
$description = isset($_POST['description']) ? clean_input($_POST['description']) : null;
$due_date = isset($_POST['due_date']) ? clean_input($_POST['due_date']) : null;

// Ensure fields are not empty
if (empty($title) || empty($description)) {
    echo json_encode(["error" => "Title and description are required."]);
    exit;
}

// Default task status is 'pending' for users
$task_status = 'pending'; // Users cannot set task status

// Decode JWT token to get user data
$user_data = validate_jwt($token);

// Stop immediately if token is invalid or decoding fails
if (!isset($user_data->id)) {
    echo json_encode(["error" => "Invalid or expired token."]);
    exit;
}

$user_id = $user_data->id; // Now safe to access


// Get user role from the database
$stmt = $conn->prepare("SELECT role FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

if (!$user) {
    echo json_encode(["error" => "User not found."]);
    exit;
}

$role = $user['role'];



// Admin has the ability to assign tasks to any user, but user can only create tasks for themselves
if ($role == 'admin') {
    $assigned_user_id = isset($_POST['assigned_user_id']) ? clean_input($_POST['assigned_user_id']) : null;
    if (empty($assigned_user_id)) {
        echo json_encode(["error" => "Admin must specify a user ID for task assignment."]);
        exit;
    }
    $user_id = $assigned_user_id; // Admin can assign tasks to any user
}

// Prepare SQL to insert the task
$stmt = $conn->prepare("INSERT INTO tasks (user_id, title, description, task_status, due_date) VALUES (?, ?, ?, ?, ?)");
$stmt->bind_param("issss", $user_id, $title, $description, $task_status, $due_date);

// Execute query
if ($stmt->execute()) {
    echo json_encode(["message" => "Task created successfully."]);
} else {
    echo json_encode(["error" => "Failed to create task."]);
}

$stmt->close();
$conn->close();
?>
