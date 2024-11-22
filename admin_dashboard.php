<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();

include "db_connect.php";

// Check if the user is logged in and has the admin role
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header("Location: login.php");
    exit;
}

// Pagination setup for users
$user_limit = 10; // Number of users per page
$user_page = isset($_GET['user_page']) ? (int)$_GET['user_page'] : 1; // Current page for users
$user_offset = ($user_page - 1) * $user_limit; // Offset for users query

// Pagination setup for purchases
$purchase_limit = 10; // Number of purchases per page
$purchase_page = isset($_GET['purchase_page']) ? (int)$_GET['purchase_page'] : 1; // Current page for purchases
$purchase_offset = ($purchase_page - 1) * $purchase_limit; // Offset for purchases query

// Optional: Search functionality for users
$user_search = isset($_GET['user_search']) ? "%" . $_GET['user_search'] . "%" : '%';

// Query to get users with pagination and search filter
$user_query = "SELECT id, username, email, role, created_at FROM users WHERE username LIKE ? OR email LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?";
$user_stmt = $conn->prepare($user_query);
$user_stmt->bind_param("ssii", $user_search, $user_search, $user_limit, $user_offset);
$user_stmt->execute();
$user_result = $user_stmt->get_result();

// Query to get purchases with pagination
$purchase_query = "SELECT * FROM purchases ORDER BY purchase_date DESC LIMIT ? OFFSET ?";
$purchase_stmt = $conn->prepare($purchase_query);
$purchase_stmt->bind_param("ii", $purchase_limit, $purchase_offset);
$purchase_stmt->execute();
$purchase_result = $purchase_stmt->get_result();

// Handle form submission for creating new user
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['username'])) {
    $username = $_POST['username'];
    $email = $_POST['email'];
    $role = $_POST['role'];
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    // Validate the form
    if ($password !== $confirm_password) {
        $error_message = "Passwords do not match.";
    } else {
        // Check if the email already exists
        $email_check_query = "SELECT id FROM users WHERE email = ?";
        $email_check_stmt = $conn->prepare($email_check_query);
        $email_check_stmt->bind_param("s", $email);
        $email_check_stmt->execute();
        $email_check_stmt->store_result();

        if ($email_check_stmt->num_rows > 0) {
            $error_message = "This email address is already registered.";
        } else {
            // Insert new user into the database
            $password_hash = password_hash($password, PASSWORD_DEFAULT);
            $insert_query = "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)";
            $insert_stmt = $conn->prepare($insert_query);
            $insert_stmt->bind_param("ssss", $username, $email, $password_hash, $role);
            if ($insert_stmt->execute()) {
                // Redirect to the admin dashboard after successful user creation
                header("Location: admin_dashboard.php");
                exit;
            } else {
                $error_message = "Error creating user. Please try again.";
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="admin_dashboard.css">
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }

        table th, table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: center;
        }

        table th {
            background-color: #f4f4f4;
        }

        .action-buttons {
            display: flex;
            gap: 10px;
            justify-content: center;
        }

        .action-buttons button {
            padding: 5px 10px;
            cursor: pointer;
        }

        .logout-btn {
            background-color: red;
            color: white;
            padding: 10px 15px;
            border: none;
            cursor: pointer;
            border-radius: 5px;
        }

        .search-container {
            margin: 20px;
            text-align: center;
        }

        .pagination {
            text-align: center;
            margin-top: 20px;
        }

        .pagination a {
            margin: 0 5px;
            padding: 8px 16px;
            border: 1px solid #ddd;
            text-decoration: none;
        }

        .pagination a.active {
            background-color: #007bff;
            color: white;
        }

        .pagination a:hover {
            background-color: #ddd;
        }

        .form-container {
            margin: 20px;
            padding: 20px;
            border: 1px solid #ddd;
            background-color: #f9f9f9;
        }

        .form-container input, .form-container select {
            width: 100%;
            padding: 8px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
        }

        .form-container button {
            background-color: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            cursor: pointer;
            border-radius: 5px;
        }

        .form-container button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <header class="header">
        <nav class="navbar">
            <a href="index.php" class="logo">
                <img src="image/gems_store_4-removebg-preview.png" alt="GEMS STORE Logo" style="height: 60px;">
            </a>
            <ul class="nav-links">
                <li><a href="index.php">Home</a></li>
                <li><a href="logout.php" class="logout-btn">Logout</a></li>
            </ul>
        </nav>
    </header>

    <main>
        <section class="dashboard-section">
            <h2>Admin Dashboard</h2>
            <h3>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h3>

            <!-- Display success or error messages -->
            <?php if (isset($success_message)) { echo "<p style='color: green;'>$success_message</p>"; } ?>
            <?php if (isset($error_message)) { echo "<p style='color: red;'>$error_message</p>"; } ?>

            <!-- User Management Section -->
            <h3>User Management</h3>
            <div class="search-container">
                <form method="GET" action="admin_dashboard.php">
                    <input type="text" name="user_search" placeholder="Search by username or email" value="<?php echo isset($_GET['user_search']) ? htmlspecialchars($_GET['user_search']) : ''; ?>">
                    <button type="submit">Search</button>
                </form>
            </div>

            <!-- Add New User Button -->
            <div class="search-container">
                <button onclick="document.getElementById('add-user-form').style.display='block'">Add New User</button>
            </div>

            <!-- Add New User Form -->
            <div id="add-user-form" class="form-container" style="display: none;">
                <h3>Create New User</h3>
                <form method="POST" action="admin_dashboard.php">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="email" name="email" placeholder="Email" required>
                    <select name="role" required>
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                    </select>
                    <input type="password" name="password" placeholder="Password" required>
                    <input type="password" name="confirm_password" placeholder="Confirm Password" required>
                    <button type="submit">Create User</button>
                    <button type="button" onclick="document.getElementById('add-user-form').style.display='none'">Cancel</button>
                </form>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Created At</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($user_row = $user_result->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo $user_row['id']; ?></td>
                            <td><?php echo htmlspecialchars($user_row['username']); ?></td>
                            <td><?php echo htmlspecialchars($user_row['email']); ?></td>
                            <td><?php echo htmlspecialchars($user_row['role']); ?></td>
                            <td><?php echo htmlspecialchars($user_row['created_at']); ?></td>
                            <td class="action-buttons">
                                <button onclick="editUser(<?php echo $user_row['id']; ?>)">Edit</button>
                                <button onclick="deleteUser(<?php echo $user_row['id']; ?>)">Delete</button>
                            </td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>

            <!-- Pagination for Users -->
            <div class="pagination">
                <?php
                $total_users_query = "SELECT COUNT(*) FROM users WHERE username LIKE ? OR email LIKE ?";
                $total_users_stmt = $conn->prepare($total_users_query);
                $total_users_stmt->bind_param("ss", $user_search, $user_search);
                $total_users_stmt->execute();
                $total_users_result = $total_users_stmt->get_result();
                $total_users_count = $total_users_result->fetch_row()[0];
                $total_user_pages = ceil($total_users_count / $user_limit);

                for ($i = 1; $i <= $total_user_pages; $i++) {
                    echo '<a href="admin_dashboard.php?user_page=' . $i . '" class="' . ($i == $user_page ? 'active' : '') . '">' . $i . '</a>';
                }
                ?>
            </div>

            <!-- Purchase Records Section -->
            <h3>Purchase Records</h3>
            <table>
                <thead>
                    <tr>
                        <th>Purchase ID</th>
                        <th>User ID</th>
                        <th>Item Name</th>
                        <th>Quantity</th>
                        <th>Total Price</th>
                        <th>Status</th>
                        <th>Purchase Date</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($purchase_row = $purchase_result->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo $purchase_row['id']; ?></td>
                            <td><?php echo htmlspecialchars($purchase_row['user_id']); ?></td>
                            <td><?php echo htmlspecialchars($purchase_row['item_name']); ?></td>
                            <td><?php echo htmlspecialchars($purchase_row['quantity']); ?></td>
                            <td><?php echo htmlspecialchars($purchase_row['total_price']); ?></td>
                            <td><?php echo htmlspecialchars($purchase_row['status']); ?></td>
                            <td><?php echo htmlspecialchars($purchase_row['purchase_date']); ?></td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>

            <!-- Pagination for Purchases -->
            <div class="pagination">
                <?php
                $total_purchases_query = "SELECT COUNT(*) FROM purchases";
                $total_purchases_result = $conn->query($total_purchases_query);
                $total_purchases_count = $total_purchases_result->fetch_row()[0];
                $total_purchase_pages = ceil($total_purchases_count / $purchase_limit);

                for ($i = 1; $i <= $total_purchase_pages; $i++) {
                    echo '<a href="admin_dashboard.php?purchase_page=' . $i . '" class="' . ($i == $purchase_page ? 'active' : '') . '">' . $i . '</a>';
                }
                ?>
            </div>
        </section>
    </main>

    <script>
        function editUser(userId) {
            window.location.href = "edit_user.php?id=" + userId;
        }

        function deleteUser(userId) {
            if (confirm("Are you sure you want to delete this user?")) {
                window.location.href = "delete_user.php?id=" + userId;
            }
        }
    </script>
</body>
</html>
