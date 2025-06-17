<?php 

require_once "../config/bootstrap.php";
header("Content-Type: application/json");

$email = isset($_POST["email"]) ?  clean_input(filter_var($_POST["email"], FILTER_SANITIZE_EMAIL)): null;
$password = isset($_POST["password"]) ? clean_input($_POST["password"]) : null;

if (!$email || !$password){
    respond(false, "All fields (email and password) are required");
}
// Enforce @gmail.com domain only
if (!preg_match('/^[\w\.\-]+@gmail\.com$/', $email)) {
    respond(false, "Only valid Gmail addresses are allowed.");
}

// Check user in DB
$stmt=$conn->prepare("SELECT id, name, email, password FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result=$stmt->get_result();

if ($result->num_rows === 1) {
    $user = $result->fetch_assoc();

    if (password_verify($password, $user['password'])) {

        $token = generate_jwt($payload);

      respond(true, "Login Successful." . ["token" => $token]);
    } else {
       respond(false, "Incorrect password.");
    }
} else {
    respond(false, "No user found with this email.");
}
?>