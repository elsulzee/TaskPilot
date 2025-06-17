<?php 
require_once "../config/bootstrap.php";

header("Content-Type: application/json");

$name = isset($_POST["name"]) ? clean_input($_POST["name"]) : null;
$email = isset($_POST["email"]) ? clean_input($_POST["email"]) : null;
$password = isset($_POST["password"]) ? clean_input($_POST["password"]) : null;

// Validate inputs

if(empty($name) || empty($email) || empty($password)){
   respond(false,  "All fields (name, email and password) are required.");
}

// Validate Gmail format only
if (!preg_match('/^[\w\.\-]+@gmail\.com$/', $email)) {
  respond(false,  "Only valid Gmail addresses are accepted.");
}


// Check if user already exists
$check = $conn->prepare("SELECT id FROM users WHERE email = ?");
$check->bind_param("s", $email);
$check->execute();
$result = $check->get_result();

if ($result->num_rows > 0) {
    respond(false, "User already exists with this email.");
}

// Hash the password
$hashed_password = password_hash($password, PASSWORD_DEFAULT);
$verify_token = bin2hex(random_bytes(32));

// Prepare SQL to insert users
$stmt=$conn->prepare("INSERT INTO users (name, email, password, verify_token) VALUES (?, ?, ?, ?)");
$stmt->bind_param("ssss", $name, $email, $hashed_password, $verify_token);

if($stmt->execute()){
    respond(true, "User Registered Successfully.");
} else {
    respond(false, "Failed to register User.");
}
?>