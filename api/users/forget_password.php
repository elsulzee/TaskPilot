<?php 
require_once "../config/bootstrap.php";

header("Content-Type: application/json");

$email = isset($_POST["email"]) ? clean_input(filter_var($_POST["email"], FILTER_SANITIZE_EMAIL)) : null;

if (!$email) {
  respond(false, "Email is required.");
}

if (!preg_match('/^[\w\.\-]+@gmail\.com$/', $email)) {
 respond(false, "Only valid Gmail addresses are accepted.");
}

// Check if user exists
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    respond(false, "No user found with the email.");
}
$stmt->close();

// Generate random OTP
$otp = rand(100000, 999999);
$expire = date("Y-m-d H:i:s", strtotime("+10 minutes"));

 $insertStmt = $conn->prepare("INSERT INTO password_resets (email, otp, expires_at) VALUES (?, ?, ?)");
 $insertStmt->bind_param("sss", $email, $otp, $expire);
 $insertStmt->execute();
  $insertStmt->close();

$checkStmt->close();

respond(true, "OTP sent successfully.".["otp" =>$otp]);
?>
