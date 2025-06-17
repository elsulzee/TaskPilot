<?php
require_once "../config/bootstrap.php";

header("Content-Type: application/json");

// Allow only POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(false, "Invalid request method.");
}

// Sanitize inputs
$email = isset($_POST['email']) ? clean_input(filter_var($_POST['email'], FILTER_SANITIZE_EMAIL)) : null;
$password = isset($_POST['password']) ? clean_input($_POST['password']) : null;

// Validate inputs
if (!$email || !$password) {
   respond(false, "Email and password are required.");
}

// Check if admin exists
$stmt = $conn->prepare("SELECT id, name, email, password FROM admins WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 1) {
    $admin = $result->fetch_assoc();

    if (password_verify($password, $admin['password'])) {

        $token = generate_jwt($payload);

        respond(true, "Login Successful". ["token" => $token]);
    } else {
        respond(false, "Incorrect password.");
    }
} else {
    respond(false, "No admin found with this email.");
}

$stmt->close();
$conn->close();
?>
