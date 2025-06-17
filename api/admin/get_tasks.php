<?php
require_once "../config/bootstrap.php";

header("Content-Type: application/json");

// Allow only GET requests
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
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

// ✅ Handle Pagination
$page = isset($_GET['page']) && is_numeric($_GET['page']) ? max(1, (int) clean_input($_GET['page'])) : 1;
$limit = isset($_GET['limit']) && is_numeric($_GET['limit']) ? max(1, (int) clean_input($_GET['limit'])) : 10;
$offset = ($page - 1) * $limit;

// ✅ Fetch tasks with pagination
$stmt = $conn->prepare("SELECT * FROM tasks ORDER BY created_at DESC LIMIT ? OFFSET ?");
$stmt->bind_param("ii", $limit, $offset);
$stmt->execute();
$result = $stmt->get_result();

$tasks = [];
while ($row = $result->fetch_assoc()) {
    $tasks[] = $row;
}

$stmt->close();
$conn->close();

// ✅ Final response
respond(true, "Tasks fetched successfully", [
    "page" => $page,
    "limit" => $limit,
    "tasks" => $tasks
]);  
?>
