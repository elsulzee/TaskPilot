<?php
require_once "../CONFIG/task_pilot_db.php";
require_once "../JWT/jwt_handler.php";

header("Content-Type: application/json");

// Only allow GET method
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    echo json_encode(["error" => "Invalid request method."]);
    exit;
}

// Get the token from the Authorization header
$headers = getallheaders();
if (!isset($headers['Authorization'])) {
    echo json_encode(["error" => "Authorization token required."]);
    exit;
}

$authHeader = $headers['Authorization'];
$token = str_replace("Bearer ", "", $authHeader);

// Decode token
$user_data = validate_jwt($token);
if (!$user_data) {
    echo json_encode(["error" => "Invalid or expired token."]);
    exit;
}

$user_id = $user_data->id;

// Validate task_id from URL
if (!isset($_GET['task_id']) || !is_numeric($_GET['task_id'])) {
    echo json_encode(["error" => "Task ID is required and must be numeric."]);
    exit;
}

$task_id = intval($_GET['task_id']);

// Check user's role
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

// Admins can view any task, users can only view their own
if ($role === 'admin') {
    $stmt = $conn->prepare("SELECT * FROM tasks WHERE id = ?");
    $stmt->bind_param("i", $task_id);
} else {
    $stmt = $conn->prepare("SELECT * FROM tasks WHERE id = ? AND user_id = ?");
    $stmt->bind_param("ii", $task_id, $user_id);
}

$stmt->execute();
$result = $stmt->get_result();
$task = $result->fetch_assoc();

if ($task) {
    echo json_encode(["task" => $task]);
} else {
    echo json_encode(["error" => "Task not found or access denied."]);
}

$stmt->close();
$conn->close();
?>
