<?php
// Start session
session_start();

// Include database configuration file
include "db_connect.php"; // Ensure the path to db_connect.php is correct

// Check if user is already logged in, if so, redirect to the dashboard
if (isset($_SESSION['user_id'])) {
    header("Location: index.php"); // Or your admin dashboard page
    exit;
}

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Retrieve user from the database
    $query = "SELECT * FROM users WHERE email='$email'";
    $result = mysqli_query($conn, $query);

    // Check if the query failed
    if (!$result) {
        die("Error: " . mysqli_error($conn)); // Display error if query fails
    }
    
    $user = mysqli_fetch_assoc($result);

    // Check if the user exists and the password is correct
    if ($user && password_verify($password, $user['password'])) {
        // Store user information in the session
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role']; // Store user role

        // Redirect to the correct page (admin dashboard or regular user page)
        if ($_SESSION['role'] === 'admin') {
            header("Location: index.php"); // Admin Dashboard
        } else {
            header("Location: index.php"); // Regular user home page
        }
        exit;
    } else {
        $error_message = "Invalid email or password. Please try again.";
    }
}
?>

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gems Store - Login</title>
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
                <li><a href="register.php" class="register-btn">Register</a></li>
            </ul>
        </nav>
    </header>

    <main>
        <section class="login-section">
            <h2>Login to Your Account</h2>
            <?php
            if (isset($error_message)) {
                echo "<p class='error-message'>$error_message</p>";
            }
            ?>
            <form action="login.php" method="POST" class="login-form">
                <label for="email">Email:</label>
                <input type="email" name="email" id="email" required>

                <label for="password">Password:</label>
                <div style="position: relative;">
                    <input type="password" name="password" id="password" required>
                    <button type="button" onclick="togglePassword()" class="toggle-password-button">Show</button>
                </div>

                <button type="submit" class="login-btn">Login</button>
            </form>
            <p>Don't have an account? <a href="register.php">Register here</a></p>
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
