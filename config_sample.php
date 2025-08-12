<?php
/**
 * Sample Configuration File - Safe for GitHub
 * CESA Fund Management System
 * 
 * IMPORTANT: Copy this file to config.php and fill in your actual values
 * NEVER commit config.php with real credentials to GitHub!
 */

// Database Configuration
define('DB_HOST', 'localhost');
define('DB_USERNAME', 'your_username');  // CHANGE THIS!
define('DB_PASSWORD', 'your_password');  // CHANGE THIS!
define('DB_NAME', 'fund_management');
define('DB_CHARSET', 'utf8mb4');

// Email Configuration
define('SMTP_HOST', 'smtp.gmail.com');  // Or your college SMTP server
define('SMTP_PORT', 587);
define('SMTP_USERNAME', 'your_email@gmail.com');  // CHANGE THIS!
define('SMTP_PASSWORD', 'your_app_password');     // CHANGE THIS!
define('SMTP_SECURE', 'tls');
define('SMTP_FROM_EMAIL', 'your_email@gmail.com');
define('SMTP_FROM_NAME', 'CESA Fund Management');

// Application Configuration
define('APP_NAME', 'CESA Fund Management System');
define('APP_VERSION', '1.0');
define('APP_ENVIRONMENT', 'development');  // Change to 'production' when deploying
define('APP_URL', 'http://localhost');     // Change to your actual domain
define('APP_TIMEZONE', 'Asia/Kolkata');

// Security Configuration
define('JWT_SECRET', 'change_this_to_a_random_string');  // CHANGE THIS!
define('PASSWORD_SALT', 'change_this_to_a_random_string'); // CHANGE THIS!
define('SESSION_TIMEOUT', 3600);
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_TIME', 900);

// File Upload Configuration
define('MAX_FILE_SIZE', 10485760); // 10MB
define('ALLOWED_FILE_TYPES', ['jpg', 'jpeg', 'png', 'pdf']);
define('UPLOAD_DIR', 'uploads/');

// Logging Configuration
define('LOG_LEVEL', 'INFO'); // DEBUG, INFO, WARNING, ERROR
define('LOG_FILE', 'logs/application.log');
define('ERROR_LOG_FILE', 'logs/error.log');

// Feature Flags
define('FEATURE_EMAIL_NOTIFICATIONS', true);
define('FEATURE_BULK_IMPORT', true);
define('FEATURE_EXPORT_REPORTS', true);
define('FEATURE_PAYMENT_TRACKING', true);
define('FEATURE_EVENT_MANAGEMENT', true);

// College Specific Settings
define('COLLEGE_NAME', 'Your College Name');  // CHANGE THIS!
define('COLLEGE_ADDRESS', 'College Address, City, State, PIN');
define('COLLEGE_PHONE', '+91-XXXXXXXXXX');
define('COLLEGE_EMAIL', 'info@college.edu');
define('CESA_FACULTY_ADVISOR', 'Faculty Advisor Name');
define('CESA_STUDENT_COORDINATOR', 'Student Coordinator Name');

// Fee Configuration
define('DEFAULT_FEE_AMOUNT', 300);
define('CURRENCY', 'INR');
define('PAYMENT_METHODS', ['Online', 'Cash', 'UPI']);

// Error Reporting (ENABLE IN DEVELOPMENT, DISABLE IN PRODUCTION)
if (APP_ENVIRONMENT === 'development') {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(0);
    ini_set('display_errors', 0);
}

ini_set('log_errors', 1);
ini_set('error_log', ERROR_LOG_FILE);

// Set timezone
date_default_timezone_set(APP_TIMEZONE);

// Database Connection Function
function getDatabaseConnection() {
    static $conn = null;
    
    if ($conn === null) {
        try {
            $conn = new mysqli(DB_HOST, DB_USERNAME, DB_PASSWORD, DB_NAME);
            
            if ($conn->connect_error) {
                error_log("Database connection failed: " . $conn->connect_error);
                throw new Exception("Database connection failed");
            }
            
            $conn->set_charset(DB_CHARSET);
            
        } catch (Exception $e) {
            error_log("Database connection error: " . $e->getMessage());
            throw $e;
        }
    }
    
    return $conn;
}

// Logging Function
function logMessage($level, $message, $context = []) {
    if (!is_dir(dirname(LOG_FILE))) {
        mkdir(dirname(LOG_FILE), 0755, true);
    }
    
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[$timestamp] [$level] $message";
    
    if (!empty($context)) {
        $logEntry .= " Context: " . json_encode($context);
    }
    
    $logEntry .= PHP_EOL;
    
    file_put_contents(LOG_FILE, $logEntry, FILE_APPEND | LOCK_EX);
}

// Security Functions
function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Initialize configuration
if (APP_ENVIRONMENT === 'development') {
    session_start();
}

// Log configuration load
logMessage('INFO', 'Configuration loaded successfully');
?> 