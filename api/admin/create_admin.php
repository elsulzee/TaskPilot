<?php
require_once "../config/bootstrap.php";
header("Content-Type: application/json");

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
//Proceed with logic (example for creating admin)
$name = isset ($_POST["name"]) ? clean_input($_POST["name"] ) : null;
$email = isset  ($_POST['email']) ?  clean_input($_POST["email"] ) : null;
$password =   isset ($_POST["password"]) ?   clean_input($_POST["password"] ) : null;

// Validate inputs
if (!$name || !$email || !$password) {
   respond(false, "All fields (name, email, password) are required.");
}

$hashed_password = password_hash($password, PASSWORD_DEFAULT);

// Check if admin already exists
$check = $conn->prepare("SELECT * FROM admins WHERE email = ?");
$check->bind_param("s", $email);
$check->execute();
$result = $check->get_result();

if ($result->num_rows > 0) {
   respond(false, "Admin already exists.");
}

// Insert new admin
$stmt = $conn->prepare("INSERT INTO admins (name, email, password) VALUES (?, ?, ?)");
$stmt->bind_param("ssss", $name, $email, $hashed_password);

if ($stmt->execute()) {
respond(true, "Admin created Successfully.");
} else {
   respond(false, "Failed to create Admin.");
}
?>
