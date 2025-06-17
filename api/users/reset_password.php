<?php 
require_once "../config/bootstrap.php";

header("Content-Type: application/json");

$otp = isset($_POST["otp"]) ? clean_input($_POST["otp"]) : null;
$new_password = isset($_POST["new_password"]) ? clean_input($_POST["new_password"]) : null;

if (empty($otp) || empty($new_password)) {
    respond(false, "Both OTP and new password are required.");
}

// Fetch email using OTP
$stmt = $conn->prepare("SELECT email, expires_at FROM password_resets WHERE otp = ?");
$stmt->bind_param("i", $otp);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows !== 1) {
    respond(false, "Invalid or expired OTP.");
}

$data = $result->fetch_assoc();
$expires_at = strtotime($data["expires_at"]);
$email = $data["email"];

if (time() > $expires_at) {
    respond(false, "OTP expired. Request a new one.");
}

// Hash new password
$hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

// Update password (you can check if it's `users` or `admins`)
$update = $conn->prepare("UPDATE users SET password = ? WHERE email = ?");
$update->bind_param("ss", $hashed_password, $email);

if ($update->execute()){
  respond(true, "Password Reset Successfully.");
} else {
    respond(false, "Something went wrong, Failed to reset password.");
}
?>
