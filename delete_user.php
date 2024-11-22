<?php
session_start();
include "db_connect.php";

// Check if admin is logged in
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header("Location: login.php");
    exit;
}

// Get the user ID from the URL
if (isset($_GET['id']) && is_numeric($_GET['id'])) {
    $userId = $_GET['id'];

    // Delete user from database
    $query = "DELETE FROM users WHERE id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $userId);

    if ($stmt->execute()) {
        header("Location: admin_dashboard.php");
        exit;
    } else {
        die("Error deleting user: " . $conn->error);
    }
} else {
    header("Location: admin_dashboard.php");
    exit;
}
?>
