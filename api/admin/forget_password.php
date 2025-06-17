<?php 
require_once "../config/bootstrap.php";

header("Content-Type: application/json");

// Sanitize email input
$email = isset($_POST['email']) ? clean_input($_POST['email']) : null;

// Validate email presence
if (empty($email)) {
   respond(false, "Email is required.");
}

// Check if admin exists
$stmt = $conn->prepare("SELECT id FROM admins WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows !== 1) {
  respond(false, "No admin found with this email.");
}
$stmt->close();

// Generate 6-digit OTP
$otp = rand(100000, 999999);
$expire = date("Y-m-d H:i:s", strtotime("+10 minutes"));

// Insert new reset record
$insertStmt = $conn->prepare("INSERT INTO password_resets (email, otp, expires_at) VALUES (?, ?, ?)");
$insertStmt->bind_param("sss", $email, $otp, $expire);
$insertStmt->execute();

$insertStmt->close();

// Send response (testing mode shows OTP)
respond(true, "OTP generated successfully for testing.". ["Otp" => $otp]);
?>
