<?php 
require_once "../CONFIG/task_pilot_db.php";

header("Content-Type: application/json");

// Helper to sanitize input
function clean_input($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

$data = json_decode(file_get_contents("php://input"), true);

$name = isset($data["name"]) ? clean_input($data["name"]) : null;
$email = isset($data["email"]) ? clean_input($data["email"]) : null;
$password = isset($data["password"]) ? clean_input($data["password"]) : null;
$role = isset($data["role"]) ? clean_input($data["role"]) : "user";

// Basic validation
if(!$name || strlen($name)<2){
    echo json_encode(["error" => "Invalid name"]);
    exit;
}
if(!filter_var($email, FILTER_VALIDATE_EMAIL) ){
    echo json_encode([
        "error" => "Invalid email"
    ]);
    exit;
}
if (!$password || strlen($password)<6){
    echo json_encode([
        "error" => "Password must be at least Six (6) words"
    ]);
    exit;
}
if (!in_array ($role, ["user", "admin"])){
    echo json_encode([
        "error" => "Invalid role specified."
    ]);
    exit;
}

// Check if email exists
$stmt=$conn->prepare("SELECT id FROM users WHERE email = ? ");
$stmt->bind_param("s", $email);
$stmt->execute();
$stmt->store_result();

if($stmt->num_rows()>0){
    echo json_encode([
        "error" => "Email already registered."
    ]);
    exit;
}
// hash password
$hashed_password = password_hash($password, PASSWORD_DEFAULT);


// INSERT INTO USERS

$stmt = $conn->prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)");
$stmt->bind_param("ssss", $name, $email, $hashed_password, $role);
if ($stmt->execute()) {
    $user_id = $stmt->insert_id;

    $verify_token = bin2hex(random_bytes(16)); // unique 32-char token

    $update = $conn->prepare("UPDATE users SET verify_token = ? WHERE email = ?");
    $update->bind_param("ss", $verify_token, $email);
    $update->execute();
    
    // Optional: Simulate sending email
    $verification_link = "http://localhost/TaskPilot/USER/verify_email.php?token=" . $verify_token;
    // For now, echo it (in real app, you'd email it)
    echo json_encode([
        "message" => "Registration successful. Please verify your email.",
        "verify_link" => $verification_link
    ]);
}
$stmt->close();
$conn->close();
?>