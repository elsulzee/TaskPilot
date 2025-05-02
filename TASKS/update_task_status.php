<?php
require_once "../CONFIG/task_pilot_db.php"; // Include DB connection
require_once "../JWT/jwt_handler.php"; // Include JWT handler for verifying token

header("Content-Type: application/json");

// Check for PUT method (for updating)
if ($_SERVER['REQUEST_METHOD'] !== 'PUT') {
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

// Check for task ID and status
$task_id = isset($_GET['task_id']) ? clean_input($_GET['task_id']) : null;
$task_status = isset($_POST['task_status']) ? clean_input($_POST['task_status']) : null;

// Ensure valid task ID and status
if (empty($task_id) || !in_array($task_status, ['pending', 'in_progress', 'completed'])) {
    echo json_encode(["error" => "Valid task ID and status are required."]);
    exit;
}

// Get user role from the database
$stmt = $conn->prepare("SELECT role FROM users WHERE id = ?");
$stmt->bind_param("i", $user_data['id']);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

if ($user && $user['role'] === 'admin') {
    // Admin is allowed to update task status
    $stmt = $conn->prepare("UPDATE tasks SET task_status = ? WHERE id = ?");
    $stmt->bind_param("si", $task_status, $task_id);

    if ($stmt->execute()) {
        echo json_encode(["message" => "Task status updated successfully."]);
    } else {
        echo json_encode(["error" => "Failed to update task status."]);
    }
} else {
    echo json_encode(["error" => "Only admins can update task status."]);
}

$stmt->close();
$conn->close();
?>
