<?php
// Start session to handle messages
session_start();

// Include database configuration file
include "db_connect.php"; // Ensure the path to db_connect.php is correct

// Verify that connection exists
if (!isset($conn)) {
    die("Database connection is not set.");
}

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $email = $_POST['email'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);

    // Check if email already exists
    $check_email = "SELECT * FROM users WHERE email='$email'";
    $result = mysqli_query($conn, $check_email);

    if ($result && mysqli_num_rows($result) > 0) {
        $error_message = "Email already registered!";
    } else {
        // Insert new user into the database, including created_at timestamp
        $query = "INSERT INTO users (username, email, password, created_at) VALUES ('$username', '$email', '$password', NOW())";
        if (mysqli_query($conn, $query)) {
            $_SESSION['success_message'] = "Registration successful! You can now log in.";
            header("Location: login.php");
            exit;
        } else {
            $error_message = "Error: Could not register. Please try again.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gems Store - Register</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>
    <header class="header">
        <nav class="navbar">
            <a href="index.php" class="logo">
                <img src="image/gems_store_4-removebg-preview.png" alt="GEMS STORE Logo" style="height: 60px;">
            </a>
            <ul class="nav-links">
                <li><a href="index.php">Home</a></li>
                <li><a href="#">Blog</a></li>
                <li><a href="login.php" class="login-btn">Login</a></li>
            </ul>
        </nav>
    </header>

    <main>
        <section class="register-section">
            <h2>Create an Account</h2>
            <?php
            if (isset($error_message)) {
                echo "<p class='error-message'>$error_message</p>";
            }
            ?>
            <form action="register.php" method="POST" class="register-form">
                <label for="username">Username:</label>
                <input type="text" name="username" id="username" required>
 
                <label for="email">Email:</label>
                <input type="email" name="email" id="email" required>

                <label for="password">Password:</label>
                <div style="position: relative;">
                    <input type="password" name="password" id="password" required>
                    <button type="button" onclick="togglePassword()" class="toggle-password-button">Show</button>
                </div>

                <button type="submit" class="register-btn">Register</button>
            </form>
            <p>Already have an account? <a href="login.php">Log in</a></p>
        </section>
    </main>

    <script>
    function togglePassword() {
        var passwordField = document.getElementById("password");
        var toggleButton = passwordField.nextElementSibling;
        if (passwordField.type === "password") {
            passwordField.type = "text";
            toggleButton.textContent = "Hide";
        } else {
            passwordField.type = "password";
            toggleButton.textContent = "Show";
        }
    }
    </script>
</body>
</html>
