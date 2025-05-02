<?php
header("Content-Type: application/json");

// include database and JWT handler
require_once("../CONFIG/task_pilot_db.php");
require_once("../JWT/jwt_handler.php");

// Ensure POST method
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(["error" => "Invalid request method."]);
    exit;
}
function clean_input($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}
// Sanitize and validate inputs
$email = isset($_POST['email']) ? clean_input(filter_var($_POST['email'], FILTER_SANITIZE_EMAIL)) : null;
$password = isset($_POST['password']) ? clean_input($_POST['password']) : null;

// Check for empty fields
if (!$email || !$password) {
    echo json_encode(["error" => "Email and password are required."]);
    exit;
}

// Enforce @gmail.com domain only
if (!preg_match('/^[\w\.\-]+@gmail\.com$/', $email)) {
    echo json_encode(["error" => "Only valid Gmail addresses are allowed."]);
    exit;
}

// Check user in DB
$stmt = $conn->prepare("SELECT id, name, email, password FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 1) {
    $user = $result->fetch_assoc();

    if (password_verify($password, $user['password'])) {
        // Valid user, generate token
        $payload = [
            "id" => $user['id'],
            "name" => $user['name'],
            "email" => $user['email']
        ];

        $token = generate_jwt($payload);

        echo json_encode([
            "message" => "Login successful",
            "token" => $token
        ]);
    } else {
        echo json_encode(["error" => "Incorrect password."]);
    }
} else {
    echo json_encode(["error" => "No user found with this email."]);
}
?>
