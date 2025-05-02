<?php
require_once "../CONFIG/task_pilot_db.php";
require_once "../JWT/jwt_handler.php";

header("Content-Type: application/json");

// 1. Ensure it's a POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(["error" => "Invalid request method."]);
    exit;
}

// 2. Clean input function
function clean_input($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// 3. Check for Authorization token
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

// 4. Get user role
$stmt = $conn->prepare("SELECT role FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$stmt->close();

if (!$user) {
    echo json_encode(["error" => "User not found."]);
    exit;
}

$role = $user['role'];

// 5. Gather task inputs
$task_id     = isset($_POST['id']) ? (int) $_POST['id'] : null;
$title       = isset($_POST['title']) ? clean_input($_POST['title']) : null;
$description = isset($_POST['description']) ? clean_input($_POST['description']) : null;
$task_status = isset($_POST['task_status']) ? clean_input($_POST['task_status']) : null;
$due_date    = isset($_POST['due_date']) ? clean_input($_POST['due_date']) : null;

if (!$task_id) {
    echo json_encode(["error" => "Task ID is required."]);
    exit;
}

// 6. Fetch task to ensure it exists
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
$stmt->close();

if (!$task) {
    echo json_encode(["error" => "Task not found or access denied."]);
    exit;
}

// 7. Fallback to existing values if fields are not sent
$updated_title       = $title ?: $task['title'];
$updated_description = $description ?: $task['description'];
$updated_status      = $task_status ?: $task['task_status'];
$updated_due_date    = (!empty($due_date) && $due_date != '0000-00-00') ? $due_date : $task['due_date'];

// 8. Update task
$update = $conn->prepare("UPDATE tasks SET title = ?, description = ?, task_status = ?, due_date = ?, updated_at = NOW() WHERE id = ?");
$update->bind_param("ssssi", $updated_title, $updated_description, $updated_status, $updated_due_date, $task_id);

if ($update->execute()) {
    if ($update->affected_rows > 0) {
        echo json_encode(["message" => "Task updated successfully."]);
    } else {
        echo json_encode(["note" => "No changes were made."]);
    }
} else {
    echo json_encode(["error" => "Update failed."]);
}

$update->close();
$conn->close();
?>
