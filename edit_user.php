<?php
// Assuming you're using PHP to handle the user edit
// Replace this with actual DB connection and fetching code
include 'db_connect.php'; // Include your database connection file

$user_id = $_GET['id'] ?? null; // Retrieve user ID from URL parameter

if ($user_id) {
    // Fetch user data from the database based on user_id
    $user_query = "SELECT username, email, role FROM users WHERE id = ?";
    $stmt = $conn->prepare($user_query);
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        // User data found
        $user_data = $result->fetch_assoc();
    } else {
        // Handle case where user data is not found
        $error_message = "User not found.";
    }
} else {
    // Handle case where user_id is not provided
    $error_message = "Invalid user ID.";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit User - Gems Store</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="edit_user.css">
</head>
<body>

<!-- Header Section -->
<header class="header">
    <div class="logo">
        <img src="image/gems_store_4-removebg-preview.png" alt="Gems Store Logo">
    </div>
    <div class="nav-links">
        <a href="dashboard.php">Home</a>
        <a href="logout.php" class="logout">Logout</a>
    </div>
</header>

<!-- Dashboard Section -->
<div class="dashboard-section">
    <h2>Edit User</h2>
    <h3>Update user details below</h3>

    <!-- Display error message if any -->
    <?php if (isset($error_message)) { echo "<p style='color: red;'>$error_message</p>"; } ?>

    <!-- Back Button -->
    <a href="admin_dashboard.php" class="back-btn" style="display: inline-block; margin-bottom: 20px; padding: 10px 20px; background-color: #f4f4f4; border: 1px solid #ddd; text-decoration: none; color: #333; border-radius: 5px;">Back</a>

    <!-- Edit User Form -->
    <form action="update_user.php" method="POST">
        <input type="hidden" name="id" value="<?= htmlspecialchars($user_id) ?>">

        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" value="<?= htmlspecialchars($user_data['username']) ?>" required>
        </div>

        <div class="form-group">
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" value="<?= htmlspecialchars($user_data['email']) ?>" required>
        </div>

        <div class="form-group">
            <label for="role">Role:</label>
            <select id="role" name="role" required>
                <option value="user" <?= $user_data['role'] == 'user' ? 'selected' : '' ?>>User</option>
                <option value="admin" <?= $user_data['role'] == 'admin' ? 'selected' : '' ?>>Admin</option>
            </select>
        </div>

        <h3>Change Password</h3>
        
        <!-- Current Password Input -->
        <div class="form-group">
            <label for="current_password">Current Password:</label>
            <input type="password" id="current_password" name="current_password" required>
        </div>

        <!-- New Password Input -->
        <div class="form-group">
            <label for="new_password">New Password:</label>
            <input type="password" id="new_password" name="new_password" required>
        </div>

        <!-- Confirm New Password Input -->
        <div class="form-group">
            <label for="confirm_password">Confirm New Password:</label>
            <input type="password" id="confirm_password" name="confirm_password" required>
        </div>

        <button type="submit">Update</button>
    </form>
</div>

</body>
</html>
