<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

$conn = new mysqli('localhost', 'vulnuser', 'vulnpass', 'insecure_login');

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user = $_POST['username'];
    $pass = $_POST['password'];

    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
    $stmt->bind_param("ss", $user, $pass);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result && $result->num_rows > 0) {
        echo "Login successful!";
    } else {
        echo "Login failed!";
    }

    $stmt->close();
}
?>

<form method="POST">
    Username: <input type="text" name="username"><br>
    Password: <input type="text" name="password"><br>
    <input type="submit" value="Login">
</form>