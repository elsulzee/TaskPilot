<?php 

header("Content-Type: application/json");

require_once "../CONFIG/task_pilot_db.php";
require_once "../JWT/jwt_handler.php";

function clean_input($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// Sanitize email input
$email = isset($_POST['email']) ? clean_input(filter_var($_POST['email'], FILTER_SANITIZE_EMAIL)) : null;

// Validate email presence
if (empty($email)) {
    echo json_encode(["error" => "Email is required."]);
    exit;
}

if (!preg_match('/^[\w\.\-]+@gmail\.com$/', $email)) {
    echo json_encode(["error" => "Only valid Gmail addresses are accepted."]);
    exit;
}

// Check if user exists
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows !== 1) {
    echo json_encode(["error" => "No user found with this email."]);
    exit;
}

// Generate 6-digit OTP
$otp = rand(100000, 999999);

// Save OTP into a new `password_resets` table
$expire = date("Y-m-d H:i:s", strtotime("+10 minutes"));

// Check if there's already an existing reset request
$checkStmt = $conn->prepare("SELECT id FROM password_resets WHERE email = ?");
$checkStmt->bind_param("s", $email);
$checkStmt->execute();
$checkResult = $checkStmt->get_result();

if ($checkResult->num_rows > 0) {
    // Update existing record
    $updateStmt = $conn->prepare("UPDATE password_resets SET otp = ?, expires_at = ? WHERE email = ?");
    $updateStmt->bind_param("sss", $otp, $expire, $email);
    $updateStmt->execute();
} else {
    // Insert new record
    $insertStmt = $conn->prepare("INSERT INTO password_resets (email, otp, expires_at) VALUES (?, ?, ?)");
    $insertStmt->bind_param("sss", $email, $otp, $expire);
    $insertStmt->execute();
}

echo json_encode([
    "message" => "OTP sent successfully.",
    "otp" => $otp 
]);
?>