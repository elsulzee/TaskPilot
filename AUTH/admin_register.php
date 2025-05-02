<?php
require_once "../CONFIG/task_pilot_db.php";
require_once "../JWT/jwt_handler.php"; 

header("Content-Type: application/json");

// Check for POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(["error" => "Invalid request method."]);
    exit;
}

// Clean input function
function clean_input($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// Get data from POST request
$name = isset($_POST['name']) ? clean_input($_POST['name']) : null;
$password = isset($_POST['password']) ? clean_input($_POST['password']) : null;
$email = isset($_POST['email']) ? clean_input($_POST['email']) : null;

// Ensure all fields are provided
if (empty($name) || empty($password) || empty($email)) {
    echo json_encode(["error" => "name, email, and password are required."]);
    exit;
}

// Hash the password
$hashed_password = password_hash($password, PASSWORD_DEFAULT);

// Prepare SQL to insert admin
$stmt = $conn->prepare("INSERT INTO users (name, password, email, role) VALUES (?, ?, ?, 'admin')");
$stmt->bind_param("sss", $name, $hashed_password, $email);

// Execute query
if ($stmt->execute()) {
    echo json_encode(["message" => "Admin registered successfully."]);
} else {
    echo json_encode(["error" => "Failed to register admin."]);
}

$stmt->close();
$conn->close();
?>
