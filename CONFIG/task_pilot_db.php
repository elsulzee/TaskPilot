<?php 
header("Content-Type: application/json");

$host = "localhost";
$username = "root";
$password = "";
$db_name = "task_pilot";

$conn = new mysqli($host, $username, $password, $db_name);

if($conn->connect_error){
    die (json_encode(["error"=> "Database Connection Failed:". $conn->connect_error]));
}
?>