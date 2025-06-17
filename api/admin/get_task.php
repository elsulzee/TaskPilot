<?php 
require_once "./config/bootstrap.php";

header("Content-Type: application/json");

if ($_SERVER["REQUEST_METHOD"] !=="GET"){
    respond(false, "Invalid Request Method");
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

$admin_id = $decoded[' id'];

// Validate admin ID from database
$admin_check = $conn->prepare("SELECT id FROM admins WHERE id = ?");
$admin_check->bind_param("i", $admin_id);
$admin_check->execute();
$admin_result = $admin_check->get_result();

if ($admin_result->num_rows === 0) {
   respond(false, " Invalid admin or token inserted");
}

// Get task_id from URL query

$task_id = isset($_GET["task_id"]) ? clean_input($_GET["task_id"]) : 0;

if (!$task_id){
    respond(false, "Task id is Required and Must Be Numeric.");
}

// Confirm task exists
$stmt = $conn->prepare("SELECT id FROM tasks WHERE id = ?");
$stmt->bind_param("i", $task_id);
$stmt->execute();
$result=$stmt->get_result();
$task=$result->fetch_assoc();

if (!$task){
    respond(false, "Task not found.");
} else {
    respond(true, "Task Fetched Successfully.", $task);
}

?>