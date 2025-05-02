<?php
header("Content-Type: application/json");
require_once("../CONFIG/task_pilot_db.php");

function clean_input($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}
// Sanitize inputs
$email = isset($_POST['email']) ? clean_input(filter_var($_POST['email'], FILTER_SANITIZE_EMAIL)) : null;
$otp = isset($_POST["otp"])? clean_input($_POST["otp"]) : null;
$new_password = isset($_POST['new_password'])? clean_input($_POST["new_password"]) : null;

// Validate inputs
if (empty($email) || empty($otp) || empty($new_password)) {
    echo json_encode(["error" => "All fields are required."]);
    exit;
}

if (!preg_match('/^[\w\.\-]+@gmail\.com$/', $email)) {
    echo json_encode(["error" => "Only valid Gmail addresses are accepted."]);
    exit;
}

// Check for valid OTP in the DB
$stmt = $conn->prepare("SELECT * FROM password_resets WHERE email = ? AND otp = ?");
$stmt->bind_param("ss", $email, $otp);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows !== 1) {
    echo json_encode(["error" => "Invalid OTP or email."]);
    exit;
}

$data = $result->fetch_assoc();
$expires_at = strtotime($data['expires_at']);
$current_time = time();

if ($current_time > $expires_at) {
    echo json_encode(["error" => "OTP has expired. Please request a new one."]);
    exit;
}

// Hash new password
$hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

// Update user password
$update = $conn->prepare("UPDATE users SET password = ? WHERE email = ?");
$update->bind_param("ss", $hashed_password, $email);
$update->execute();

// Clear used OTP
$delete = $conn->prepare("DELETE FROM password_resets WHERE email = ?");
$delete->bind_param("s", $email);
$delete->execute();

echo json_encode(["message" => "Password reset successful. You can now login."]);
?>
