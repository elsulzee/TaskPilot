<?php
require_once "../CONFIG/task_pilot_db.php";
require_once "../JWT/jwt_handler.php";

header("Content-Type: application/json");

// Allow only GET
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    echo json_encode(["error" => "Invalid request method."]);
    exit;
}

// Auth token check
$headers = getallheaders();
if (!isset($headers['Authorization'])) {
    echo json_encode(["error" => "Authorization token required."]);
    exit;
}

$token = str_replace("Bearer ", "", $headers['Authorization']);
$user_data = validate_jwt($token);
if (!$user_data || !isset($user_data->id)) {
    echo json_encode(["error" => "Invalid or expired token."]);
    exit;
}

$user_id = $user_data->id;

// Get user role
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

// Pagination defaults
$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$limit = isset($_GET['limit']) ? max(1, (int)$_GET['limit']) : 10;
$offset = ($page - 1) * $limit;

// Prepare SQL
if ($role === 'admin') {
    $stmt = $conn->prepare("SELECT * FROM tasks ORDER BY created_at DESC LIMIT ? OFFSET ?");
    $stmt->bind_param("ii", $limit, $offset);
} else {
    $stmt = $conn->prepare("SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?");
    $stmt->bind_param("iii", $user_id, $limit, $offset);
}

$stmt->execute();
$result = $stmt->get_result();
$tasks = [];

while ($row = $result->fetch_assoc()) {
    $tasks[] = $row;
}

echo json_encode([
    "page" => $page,
    "limit" => $limit,
    "tasks" => $tasks
]);

$stmt->close();
$conn->close();
