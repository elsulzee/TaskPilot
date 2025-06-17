<?php
require_once "../config/bootstrap.php";

header("Content-Type: application/json");

// 1. Ensure it's a POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
   respond(false, "Invalid request method.");
}

//  2 Get Authorization header
$header = apache_request_headers();
$authHeader = $header["Authorization"] ?? '';
$token = trim(str_replace("Bearer", '', $authHeader));

if (empty($token)) {
    respond(false, "Unauthorized: token is missing.");
}

// 3 Decode JWT token
$user_data = validate_jwt($token);
if (!$user_data || !isset($user_data->id)) {
    respond(false, "Invalid or expired token.");
}

$user_id = $user_data->id;

// 4 Validate user ID exists in database
$user_check = $conn->prepare("SELECT id FROM users WHERE id = ?");
$user_check->bind_param("i", $user_id);
$user_check->execute();
$user_result = $user_check->get_result();
$user_check->close();

if ($user_result->num_rows === 0) {
    respond(false, "Invalid user or token.");
}

// 4. Gather inputs
$task_id     = isset($_POST['id']) ? clean_input($_POST['id']) : 0;
$title       = isset($_POST['title']) ? clean_input($_POST['title']) : null;
$description = isset($_POST['description']) ? clean_input($_POST['description']) : null;
$task_status = isset($_POST['task_status']) ? clean_input($_POST['task_status']) : null;
$due_date    = isset($_POST['due_date']) ? clean_input($_POST['due_date']) : null;

if (!$task_id) {
    respond(false, "Task ID is required.");
}

// 5. Fetch task — only if it belongs to the logged-in user
$stmt = $conn->prepare("SELECT * FROM tasks WHERE id = ? AND user_id = ?");
$stmt->bind_param("ii", $task_id, $user_id);
$stmt->execute();
$result = $stmt->get_result();
$task = $result->fetch_assoc();
$stmt->close();

if (!$task) {
    respond(false, "Task not found or access denied.");
}

// 6. Fallback to existing values
$updated_title       = $title ?: $task['title'];
$updated_description = $description ?: $task['description'];
$updated_status      = $task_status ?: $task['task_status'];
$updated_due_date    = (!empty($due_date) && $due_date !== '0000-00-00') ? $due_date : $task['due_date'];

// 7. Update task
$update = $conn->prepare("UPDATE tasks SET title = ?, description = ?, task_status = ?, due_date = ?, updated_at = NOW() WHERE id = ? AND user_id = ?");
$update->bind_param("ssssii", $updated_title, $updated_description, $updated_status, $updated_due_date, $task_id, $user_id);

if ($update->execute()) {
    if ($update->affected_rows > 0) {
        respond(true, "Task updated successfully.");
    } else {
        respond(false, "Note", ["No changes were made."]);
    }
} else {
    respond(false, "Update failed.");
}

$update->close();
$conn->close();
?>
