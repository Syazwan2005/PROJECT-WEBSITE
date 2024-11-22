<?php
// Assuming you're using PHP to handle the user edit
// Example code to retrieve user data from the database
// Make sure to replace this with actual DB fetching code
include('db_connect.php'); // Assuming your DB connection is in this file

// Fetch user data function
function fetchUserData($user_id) {
    global $conn;
    $sql = "SELECT * FROM users WHERE id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    return $stmt->get_result()->fetch_assoc();
}

// Update user data function
function updateUserData($user_id, $username, $email, $role, $password = null) {
    global $conn;
    $sql = "UPDATE users SET username = ?, email = ?, role = ?";

    // If password is provided, update it
    if ($password) {
        $sql .= ", password = ?";
    }

    $sql .= " WHERE id = ?";
    
    $stmt = $conn->prepare($sql);
    if ($password) {
        $stmt->bind_param("ssssi", $username, $email, $role, $password, $user_id);
    } else {
        $stmt->bind_param("sssi", $username, $email, $role, $user_id);
    }
    $stmt->execute();
}

// Process the form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user_id = $_POST['id'];
    $username = $_POST['username'];
    $email = $_POST['email'];
    $role = $_POST['role'];
    $current_password = $_POST['current_password'];
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];

    // Fetch the user data from the database
    $user_data = fetchUserData($user_id);

    // Check if the user exists
    if (!$user_data) {
        echo "User not found.";
        exit;
    }

    // Verify the current password
    if (!password_verify($current_password, $user_data['password'])) {
        echo "Incorrect current password!";
        exit;
    }

    // If new password is provided, check if new password and confirm password match
    if (!empty($new_password)) {
        if ($new_password !== $confirm_password) {
            echo "New password and confirmation do not match!";
            exit;
        }

        // Hash the new password
        $new_password_hashed = password_hash($new_password, PASSWORD_DEFAULT);

        // Update user data with new password
        updateUserData($user_id, $username, $email, $role, $new_password_hashed);
    } else {
        // If no new password is provided, just update the user details without changing the password
        updateUserData($user_id, $username, $email, $role);
    }

    // Redirect to admin dashboard
    header('Location: admin_dashboard.php');
    exit; // Make sure to call exit after header to stop further execution
}
?>
