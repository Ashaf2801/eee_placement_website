<?php
session_start();
header('Content-Type: application/json');

// Database configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'your_username');
define('DB_PASS', 'your_password');
define('DB_NAME', 'your_database');

// Function to create database connection
function createConnection() {
    try {
        $pdo = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
            DB_USER,
            DB_PASS,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false
            ]
        );
        return $pdo;
    } catch (PDOException $e) {
        error_log("Database connection failed: " . $e->getMessage());
        return null;
    }
}

// Function to sanitize input
function sanitizeInput($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// Function to verify password
function verifyPassword($inputPassword, $hashedPassword) {
    return password_verify($inputPassword, $hashedPassword);
}

// Main login processing
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Get and sanitize input data
        $username = sanitizeInput($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $userType = sanitizeInput($_POST['userType'] ?? '');
        
        // Validate input
        if (empty($username) || empty($password) || empty($userType)) {
            throw new Exception('All fields are required');
        }
        
        if (strlen($username) < 3) {
            throw new Exception('Username must be at least 3 characters long');
        }
        
        if (strlen($password) < 6) {
            throw new Exception('Password must be at least 6 characters long');
        }
        
        if (!in_array($userType, ['staff', 'student'])) {
            throw new Exception('Invalid user type');
        }
        
        // Create database connection
        $pdo = createConnection();
        if (!$pdo) {
            throw new Exception('Database connection failed');
        }
        
        // Prepare SQL query based on user type
        if ($userType === 'staff') {
            $sql = "SELECT id, username, password, full_name, email, department, status 
                    FROM staff_users 
                    WHERE username = :username AND status = 'active'";
        } else {
            $sql = "SELECT id, student_id, password, full_name, email, department, status 
                    FROM student_users 
                    WHERE student_id = :username AND status = 'active'";
        }
        
        $stmt = $pdo->prepare($sql);
        $stmt->bindParam(':username', $username, PDO::PARAM_STR);
        $stmt->execute();
        
        $user = $stmt->fetch();
        
        if (!$user) {
            throw new Exception('Invalid username or password');
        }
        
        // Verify password
        if (!verifyPassword($password, $user['password'])) {
            throw new Exception('Invalid username or password');
        }
        
        // Login successful - create session
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_type'] = $userType;
        $_SESSION['username'] = $userType === 'staff' ? $user['username'] : $user['student_id'];
        $_SESSION['full_name'] = $user['full_name'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['department'] = $user['department'];
        $_SESSION['login_time'] = time();
        
        // Log successful login
        $logSql = "INSERT INTO login_logs (user_id, user_type, username, login_time, ip_address, user_agent) 
                   VALUES (:user_id, :user_type, :username, NOW(), :ip_address, :user_agent)";
        $logStmt = $pdo->prepare($logSql);
        $logStmt->execute([
            ':user_id' => $user['id'],
            ':user_type' => $userType,
            ':username' => $_SESSION['username'],
            ':ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
            ':user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        ]);
        
        // Return success response
        echo json_encode([
            'success' => true,
            'message' => 'Login successful! Redirecting...',
            'user_type' => $userType,
            'redirect' => $userType === 'staff' ? 'staff_dashboard.php' : 'student_dashboard.php'
        ]);
        
    } catch (Exception $e) {
        // Log failed login attempt
        if (isset($pdo) && $pdo) {
            try {
                $failLogSql = "INSERT INTO failed_login_attempts (username, user_type, attempt_time, ip_address, user_agent, error_message) 
                               VALUES (:username, :user_type, NOW(), :ip_address, :user_agent, :error_message)";
                $failLogStmt = $pdo->prepare($failLogSql);
                $failLogStmt->execute([
                    ':username' => $username ?? 'Unknown',
                    ':user_type' => $userType ?? 'Unknown',
                    ':ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
                    ':user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
                    ':error_message' => $e->getMessage()
                ]);
            } catch (Exception $logError) {
                error_log("Failed to log failed login attempt: " . $logError->getMessage());
            }
        }
        
        // Return error response
        echo json_encode([
            'success' => false,
            'message' => $e->getMessage()
        ]);
    }
} else {
    // Invalid request method
    echo json_encode([
        'success' => false,
        'message' => 'Invalid request method'
    ]);
}
?>
