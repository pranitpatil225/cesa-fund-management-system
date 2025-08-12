<?php
// Ensure composer autoload is included FIRST
require 'vendor/autoload.php'; // IMPORTANT: This line MUST be present and correctly point to your vendor folder

// Enable error logging for debugging
ini_set('log_errors', 'On');
ini_set('error_log', __DIR__ . '/php_errors.log'); // Ensure this path is writable by the web server

// Log script start
error_log("api.php: Script started at " . date('Y-m-d H:i:s'));

// PhpSpreadsheet 'use' statements must come AFTER require 'vendor/autoload.php';
use PhpOffice\PhpSpreadsheet\IOFactory;
use PhpOffice\PhpSpreadsheet\Reader\Exception as ReaderException;

// Include the database connection.
// This file should *only* establish the $conn connection and handle its own errors internally.
require_once 'db_connect.php'; // Assuming this sets up a $conn (mysqli) object

// Set headers for JSON response and CORS
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *'); // Consider restricting this to your frontend domain in production (e.g., 'http://localhost:3000')
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight OPTIONS requests (important for CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Check if the database connection was successful from db_connect.php
if (!$conn) {
    error_log("api.php: FATAL ERROR - Database connection failed, \$conn is null.");
    http_response_code(500);
    die(json_encode(["error" => "Server experienced a database connection issue. Please try again later."]));
}

// Helper function for consistent error responses
function error_response($statusCode, $message) {
    http_response_code($statusCode);
    echo json_encode(['error' => $message]);
    error_log("API Error: " . $message);
    exit();
}

// Function to generate a random password (can be used if password is NOT provided in excel, currently it is)
function generateRandomPassword($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-_=+';
    $password = '';
    for ($i = 0; $i < $length; $i++) {
        $password .= $characters[rand(0, strlen($characters) - 1)];
    }
    return $password;
}

// --- AUTHENTICATION FUNCTIONS ---

/**
 * Authenticates a user based on email/PRN and password (for initial login).
 * This function is used ONLY by the 'login' action.
 * @param mysqli $conn The database connection.
 * @param string $emailOrPrn User's email or PRN.
 * @param string $password User's plain-text password.
 * @return array|false User data if authenticated, false otherwise.
 */
function authenticate_credentials($conn, $emailOrPrn, $password) {
    error_log("authenticate_credentials(): Function called for user: " . $emailOrPrn);

    // Attempt to find user by email OR PRN
    $stmt = $conn->prepare("SELECT user_id, name, email, prn, password, role, status FROM users WHERE email = ? OR prn = ?"); // Assuming 'password' column stores hashes
    if (!$stmt) {
        error_log("authenticate_credentials(): Prepare failed: " . $conn->error);
        return false;
    }
    $stmt->bind_param("ss", $emailOrPrn, $emailOrPrn);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        // Verify the plain-text password against the stored hash
        if (password_verify($password, $user['password'])) { // Assuming 'password' column stores the hash
            error_log("authenticate_credentials(): User authenticated successfully: " . $emailOrPrn . ", Role: " . $user['role'] . ", Status: " . $user['status']);
            unset($user['password']); // Remove sensitive data before returning
            return $user;
        } else {
            error_log("authenticate_credentials(): Password verification failed for user: " . $emailOrPrn);
        }
    } else {
        error_log("authenticate_credentials(): No user found or multiple users found for input: " . $emailOrPrn);
    }
    return false;
}

/**
 * Authenticates the user based on a Bearer token from the Authorization header.
 * If authentication fails (invalid token, expired, inactive user), it sends an error response and exits.
 * This function is used for ALL protected API endpoints (after initial login).
 *
 * @param mysqli $conn The database connection.
 * @return array The authenticated user's data (if successful).
 */
function authenticate_token(mysqli $conn): array {
    $headers = apache_request_headers();
    $authHeader = $headers['Authorization'] ?? '';

    if (empty($authHeader) || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        http_response_code(401);
        echo json_encode(["error" => "Authentication required: Bearer token missing or malformed."]);
        exit();
    }

    $token = $matches[1];

    try {
        // Fetch user data by token
        $stmt = $conn->prepare("SELECT user_id, name, email, role, status, token_expiry FROM users WHERE token = ?");
        if (!$stmt) {
            error_log("authenticate_token(): Prepare failed: " . $conn->error);
            http_response_code(500);
            echo json_encode(["error" => "Database error during token validation preparation."]);
            exit();
        }
        $stmt->bind_param("s", $token);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();

        if (!$user) {
            http_response_code(401);
            echo json_encode(["error" => "Invalid or unrecognized token."]);
            exit();
        }

        // Check token expiry
        if ($user['token_expiry'] && $user['token_expiry'] < time()) {
            http_response_code(401);
            echo json_encode(["error" => "Token expired. Please log in again."]);
            // Optional: Clear the expired token from the database
            // $updateStmt = $conn->prepare("UPDATE users SET token = NULL, token_expiry = NULL WHERE user_id = ?");
            // $updateStmt->bind_param("i", $user['user_id']);
            // $updateStmt->execute();
            exit();
        }

        // Authentication successful. Remove sensitive info before returning.
        unset($user['token']);
        unset($user['token_expiry']);
        return $user;

    } catch (Exception $e) { // Catching general Exception for mysqli errors
        error_log("authenticate_token(): Error during token validation: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(["error" => "Server error during token validation: " . $e->getMessage()]);
        exit();
    }
}

// Add this helper function at the top with other helper functions
function get_current_fee_amount($conn) {
    $stmt = $conn->prepare("SELECT fee_amount FROM fee_settings ORDER BY id DESC LIMIT 1");
    if (!$stmt) {
        throw new Exception("Failed to prepare statement for getting fee amount: " . $conn->error);
    }
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 0) {
        throw new Exception("No fee amount found in settings");
    }
    $fee_amount = $result->fetch_assoc()['fee_amount'];
    $stmt->close();
    return $fee_amount;
}

// --- MAIN API ENDPOINT LOGIC ---

$action = $_GET['action'] ?? '';
error_log("api.php: Action requested: " . $action);

$authenticatedUser = null; // Variable to hold authenticated user data for protected routes

// Centralized token authentication for all actions EXCEPT 'login' and 'register_student'
// 'bulk_upload_students' also needs authentication.
if ($action !== 'login' && $action !== 'register_student' && $action !== 'forgot_password' && $action !== 'reset_password') {
    $authenticatedUser = authenticate_token($conn); // If token is invalid, this function will exit.
    // If execution reaches here, $authenticatedUser holds the validated user data.
}

switch ($action) {
    case 'login':
        error_log("api.php: Handling login action.");
        $data = json_decode(file_get_contents("php://input"), true);
        $emailOrPrn = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        if (empty($emailOrPrn) || empty($password)) {
            error_response(400, "Email/PRN and password are required.");
        }

        // Use authenticate_credentials for initial username/password verification
        $user = authenticate_credentials($conn, $emailOrPrn, $password);

        if ($user) {
            // User authenticated successfully, now generate a token
            $token = bin2hex(random_bytes(32)); // Generate a random 64-character hex token
            $token_expiry = time() + (3600 * 24); // Token valid for 24 hours

            // Store the token and its expiry in the database
            $stmt = $conn->prepare("UPDATE users SET token = ?, token_expiry = ? WHERE user_id = ?");
            if ($stmt === false) {
                error_log("login: Prepare token update failed: " . $conn->error);
                error_response(500, "Server error during token generation.");
            }
            $stmt->bind_param("sis", $token, $token_expiry, $user['user_id']);
            if (!$stmt->execute()) {
                error_log("login: Execute token update failed: " . $stmt->error);
                error_response(500, "Server error during token storage.");
            }
            $stmt->close();

            // Return user data and the generated token
            echo json_encode([
                'message' => 'Login successful',
                'user' => $user, // Already unset sensitive info in authenticate_credentials
                'token' => $token
            ]);
        } else {
            error_response(401, "Invalid email/PRN or password.");
        }
        break;

    case 'get_user_info':
        error_log("api.php: Handling get_user_info action.");
        // $authenticatedUser is already populated by authenticate_token
        echo json_encode($authenticatedUser);
        break;

    case 'register_student':
        error_log("api.php: Handling register_student action.");
        // No authentication needed for registration
        $rawData = file_get_contents("php://input");
        error_log("api.php - Raw POST data for register_student: " . $rawData);
        $data = json_decode($rawData, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("api.php - register_student: JSON Decode Error: " . json_last_error_msg());
            error_response(400, "Invalid JSON payload for registration.");
        }

        $fullName = isset($data['fullName']) ? preg_replace('/\s+/u', ' ', trim($data['fullName'])) : null;
        $prn = isset($data['prn']) ? trim($data['prn']) : null;
        $email = isset($data['email']) ? trim($data['email']) : null;
        $password = isset($data['password']) ? $data['password'] : null;
        $department = isset($data['department']) ? trim($data['department']) : null;
        $year = isset($data['year']) ? trim($data['year']) : null;

        error_log("api.php - Processed data for registration: Name='" . $fullName . "', PRN='" . $prn . "', Email='" . $email . "', Dept='" . $department . "', Year='" . $year . "'");

        // Server-side validation
        if (empty($fullName) || empty($prn) || empty($email) || empty($password) || empty($department) || empty($year)) {
            error_log("api.php - register_student: Missing required fields.");
            error_response(400, "All registration fields are required.");
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            error_log("api.php - register_student: Invalid email format.");
            error_response(400, "Invalid email format.");
        }
        if (strlen($password) < 6) { // Minimum password length
            error_log("api.php - register_student: Password too short (min 6 characters).");
            error_response(400, "Password must be at least 6 characters long.");
        }
        if (!preg_match('/^[A-Z0-9]+$/i', $prn)) {
            error_log("api.php - register_student: Invalid PRN format.");
            error_response(400, "Invalid PRN format. Only alphanumeric characters allowed.");
        }

        // Check for existing PRN or email
        $sql_check_duplicate = "SELECT COUNT(*) FROM users WHERE prn = ? OR email = ?";
        $stmt_check_duplicate = $conn->prepare($sql_check_duplicate);
        if (!$stmt_check_duplicate) {
            error_log("api.php - register_student: Prepare failed for duplicate check: " . $conn->error);
            error_response(500, "Database error during duplicate check preparation.");
        }
        $stmt_check_duplicate->bind_param("ss", $prn, $email);
        $stmt_check_duplicate->execute();
        $result_check_duplicate = $stmt_check_duplicate->get_result();
        $count_duplicate = $result_check_duplicate->fetch_row()[0];
        $stmt_check_duplicate->close();

        if ($count_duplicate > 0) {
            error_log("api.php - register_student: PRN or Email already exists.");
            error_response(409, "An account with this PRN or Email already exists."); // Conflict
        }

        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $role = 'student';
        $status = 'pending'; // New students are always pending by default

        $conn->begin_transaction();
        try {
            $sql_insert = "INSERT INTO users (name, prn, email, password, role, status, department, year) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
            $stmt_insert = $conn->prepare($sql_insert);
            if (!$stmt_insert) {
                throw new Exception("Prepare failed for student registration: " . $conn->error);
            }
            $stmt_insert->bind_param("ssssssss", $fullName, $prn, $email, $hashed_password, $role, $status, $department, $year);

            if (!$stmt_insert->execute()) {
                throw new Exception("Error executing student registration: " . $stmt_insert->error);
            }
            $new_user_id = $conn->insert_id;
            $stmt_insert->close();
            error_log("api.php - register_student: New student registered with ID: " . $new_user_id);

            // Get the current fee amount from settings
            $default_amount = get_current_fee_amount($conn);
            $default_fee_type = 'initial_registration';
            $default_status_transaction = 'pending';
            $default_method = 'Registration Default';
            $default_due_date = date('Y-m-d H:i:s', strtotime('+30 days'));

            $sql_transaction_insert = "INSERT INTO transactions (student_id, amount, status, method, timestamp, fee_type, due_date) VALUES (?, ?, ?, ?, NOW(), ?, ?)";
            $stmt_transaction = $conn->prepare($sql_transaction_insert);
            if (!$stmt_transaction) {
                throw new Exception("Prepare failed for initial student transaction: " . $conn->error);
            }
            $stmt_transaction->bind_param("iissds", $new_user_id, $default_amount, $default_status_transaction, $default_method, $default_fee_type, $default_due_date);

            if (!$stmt_transaction->execute()) {
                throw new Exception("Error executing initial student transaction: " . $stmt_transaction->error);
            }
            $stmt_transaction->close();
            error_log("api.php - register_student: Initial pending transaction created for new student ID: " . $new_user_id . ", Transaction ID: " . $conn->insert_id);


            $conn->commit();
            echo json_encode(["success" => true, "message" => "Registration successful! Your account is pending HOD approval."]);

        } catch (Exception $e) {
            $conn->rollback();
            error_log("api.php - register_student: Error during registration (rolled back): " . $e->getMessage());
            error_response(500, "Registration failed: " . $e->getMessage());
        }
        break;

    // --- Admin Actions ---
     case 'bulk_upload_students':
        error_log("api.php: Handling bulk_upload_students action. File received: " . ($_FILES['student_file']['name'] ?? 'N/A'));
        if ($authenticatedUser['role'] !== 'admin') {
            error_log("api.php - bulk_upload_students: Access denied for role " . $authenticatedUser['role']);
            error_response(403, "Access denied. Admin privileges required.");
        }

        // --- IMPORTANT: Ensure these are enabled in php.ini and Apache restarted ---
        // extension=gd
        // extension=zip
        // extension=xml  (or dom, simplexml, or php_xml.dll etc.)
        // --- END IMPORTANT ---


        $fileTmpPath = $_FILES['student_file']['tmp_name'];
        $fileName = $_FILES['student_file']['name'];
        $fileExtension = pathinfo($fileName, PATHINFO_EXTENSION);

        try {
            $allowedFileTypes = ['xlsx', 'xls', 'csv'];
            if (!in_array(strtolower($fileExtension), $allowedFileTypes)) {
                error_response(400, "Invalid file type. Only Excel (xlsx, xls) or CSV files are allowed.");
            }

            // --- DEBUG LOGS START ---
            error_log("API: About to call IOFactory::load(). Temp path: " . $fileTmpPath);
            // --- DEBUG LOGS END ---

            $spreadsheet = IOFactory::load($fileTmpPath);

            // --- DEBUG LOGS START ---
            error_log("API: IOFactory::load() successful. Getting active sheet.");
            // --- DEBUG LOGS END ---

            $sheet = $spreadsheet->getActiveSheet();
            $data = $sheet->toArray(null, true, true, false); // Change the last 'true' to 'false'

            // --- DEBUG LOGS START ---
            error_log("API: Raw data from spreadsheet (after toArray): " . print_r($data, true)); // DEBUG: LOG ALL RAW DATA
            // --- DEBUG LOGS END ---

            if (empty($data) || count($data) < 2) { // Need at least header + one row
                error_response(400, "The uploaded file is empty or contains only headers.");
            }

            // Headers from the first row, mapped to lowercase and trimmed for robust matching
            $headers = array_map('trim', array_map('strtolower', array_values($data[0]))); // CHANGE THIS LINE
unset($data[0]); // CHANGE THIS LINE (Remove header row from data)

            // --- DEBUG LOGS START ---
            error_log("API: Processed Headers: " . print_r($headers, true)); // DEBUG: LOG PROCESSED HEADERS
            // --- DEBUG LOGS END ---


            // Define expected headers for the Excel file, including 'password'
            $expectedHeaders = ['name', 'email', 'prn', 'department', 'year', 'password'];
            $headerMap = [];
            foreach ($expectedHeaders as $expectedHeader) {
                $foundKey = array_search($expectedHeader, $headers);
                if ($foundKey === false) {
                    error_response(400, "Missing required column in Excel/CSV: '" . ucfirst($expectedHeader) . "'. Please check your template.");
                }
                // --- DEBUG LOGS START ---
                error_log("API: Mapping expected header '{$expectedHeader}' to column key '{$foundKey}'");
                // --- DEBUG LOGS END ---
                $headerMap[$expectedHeader] = $foundKey;
            }

            // --- DEBUG LOGS START ---
            error_log("API: Final Header Map: " . print_r($headerMap, true)); // DEBUG: LOG HEADER MAP
            // --- DEBUG LOGS END ---


            $successCount = 0;
            $failedStudents = [];

            $conn->begin_transaction();

            foreach ($data as $rowNum => $rowData) {
                // Skip completely empty rows
                $isEmptyRow = true;
                foreach ($rowData as $cellValue) {
                    if (!empty(trim((string)$cellValue))) {
                        $isEmptyRow = false;
                        break;
                    }
                }
                if ($isEmptyRow) continue;

                // --- DEBUG LOGS START ---
                error_log("API: Processing Row " . $rowNum . ": " . print_r($rowData, true)); // DEBUG: LOG EACH ROW DATA
                // --- DEBUG LOGS END ---

                // Extract data using headerMap
                $name = trim($rowData[$headerMap['name']] ?? '');
                $email = trim($rowData[$headerMap['email']] ?? '');
                $prn = trim($rowData[$headerMap['prn']] ?? '');
                $department = trim($rowData[$headerMap['department']] ?? '');
                $year = trim($rowData[$headerMap['year']] ?? '');
                $password = (string)($rowData[$headerMap['password']] ?? ''); // Get password from Excel
                $role = 'student'; // Role is fixed as 'student'
                $status = 'pending'; // Default status for imported students

                // --- DEBUG LOGS START ---
                error_log("API: Extracted Data for Row " . $rowNum . ": Name='{$name}', Email='{$email}', PRN='{$prn}', Dept='{$department}', Year='{$year}', Password='{$password}'"); // DEBUG: LOG EXTRACTED VALUES
                // --- DEBUG LOGS END ---


                $rowErrors = [];

                // Validation
                if (empty($name)) $rowErrors[] = "Name is empty";
                if (empty($email)) $rowErrors[] = "Email is empty";
                if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $rowErrors[] = "Invalid email format";
                if (empty($prn)) $rowErrors[] = "PRN is empty";
                if (!preg_match('/^[A-Z0-9]+$/i', $prn)) $rowErrors[] = "Invalid PRN format (alphanumeric only)";
                if (empty($department)) $rowErrors[] = "Department is empty";
                if (empty($year)) $rowErrors[] = "Year is empty";
                if (empty($password)) $rowErrors[] = "Password is empty";
                if (strlen($password) < 6) $rowErrors[] = "Password must be at least 6 characters long";


                if (empty($rowErrors)) {
                    // Check for duplicate PRN or email
                    $stmt_check_duplicate = $conn->prepare("SELECT COUNT(*) FROM users WHERE prn = ? OR email = ?");
                    if (!$stmt_check_duplicate) {
                         throw new Exception("Database error preparing duplicate check: " . $conn->error);
                    }
                    $stmt_check_duplicate->bind_param("ss", $prn, $email);
                    $stmt_check_duplicate->execute();
                    $result_check_duplicate = $stmt_check_duplicate->get_result();
                    $count_duplicate = $result_check_duplicate->fetch_row()[0];
                    $stmt_check_duplicate->close();

                    if ($count_duplicate > 0) {
                        $rowErrors[] = "PRN or Email already exists in the database.";
                    }
                }

                if (empty($rowErrors)) {
                    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                    // Insert into users table
                    $sql_insert_user = "INSERT INTO users (name, prn, email, password, role, status, department, year) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
                    $stmt_insert_user = $conn->prepare($sql_insert_user);
                    if (!$stmt_insert_user) {
                        throw new Exception("Database error preparing user insert: " . $conn->error);
                    }
                    $stmt_insert_user->bind_param("ssssssss", $name, $prn, $email, $hashed_password, $role, $status, $department, $year);

                    if (!$stmt_insert_user->execute()) {
                        $rowErrors[] = "Database error inserting user: " . $stmt_insert_user->error;
                    } else {
                        $new_user_id = $conn->insert_id;
                        $stmt_insert_user->close();

                        // Get the current fee amount from settings
                        $default_amount = get_current_fee_amount($conn);
                        $default_fee_type = 'initial_registration';
                        $default_status_transaction = 'pending';
                        $default_method = 'Bulk Import';
                        $default_due_date = date('Y-m-d H:i:s', strtotime('+30 days'));

                        $sql_transaction_insert = "INSERT INTO transactions (student_id, amount, status, method, timestamp, fee_type, due_date) VALUES (?, ?, ?, ?, NOW(), ?, ?)";
                        $stmt_transaction = $conn->prepare($sql_transaction_insert);
                        if (!$stmt_transaction) {
                            throw new Exception("Database error preparing transaction insert: " . $conn->error);
                        }
                        $stmt_transaction->bind_param("iissds", $new_user_id, $default_amount, $default_status_transaction, $default_method, $default_fee_type, $default_due_date);

                        if (!$stmt_transaction->execute()) {
                            $rowErrors[] = "Database error inserting initial transaction: " . $stmt_transaction->error;
                        }
                        $stmt_transaction->close();
                    }
                }

                if (empty($rowErrors)) {
                    $successCount++;
                } else {
                    $failedStudents[] = [
                        'row' => $rowNum,
                        'name' => $name,
                        'prn' => $prn,
                        'email' => $email,
                        'errors' => $rowErrors
                    ];
                }
            }

            if (empty($failedStudents)) {
                $conn->commit();
                echo json_encode(["message" => "Successfully imported " . $successCount . " students.", "success_count" => $successCount]);
            } else {
                $conn->rollback();
                http_response_code(400); // Bad Request because some rows failed
                echo json_encode([
                    "error" => "Import completed with " . count($failedStudents) . " failures. No students were imported due to rollback.",
                    "success_count" => 0, // Indicate that no students were successfully committed
                    "failed_students" => $failedStudents
                ]);
            }

        } catch (ReaderException $e) {
            $conn->rollback();
            error_log("PhpSpreadsheet Reader Error: " . $e->getMessage());
            error_response(500, "Error reading file: " . $e->getMessage() . " Ensure file is not corrupted or is the correct format.");
        } catch (Exception $e) {
            $conn->rollback();
            error_log("Excel Import Error: " . $e->getMessage());
            error_response(500, "An error occurred during import: " . $e->getMessage());
        }
        break;

    case 'get_all_users':
        error_log("api.php: Handling get_all_users action.");
        if ($authenticatedUser['role'] !== 'admin') {
            error_log("api.php - get_all_users: Access denied for role " . $authenticatedUser['role']);
            error_response(403, "Access denied. Admin privileges required.");
        }
        $stmt = $conn->prepare("SELECT user_id, name, email, role, status, prn, department, year FROM users ORDER BY name ASC");
        if (!$stmt) {
            error_response(500, "Failed to prepare statement for get_all_users: " . $conn->error);
        }
        $stmt->execute();
        $result = $stmt->get_result();
        $users = [];
        while ($row = $result->fetch_assoc()) {
            $users[] = $row;
        }
        $stmt->close();
        error_log("api.php - get_all_users: " . count($users) . " users retrieved.");
        echo json_encode($users);
        break;

    case 'create_user': // This is for admin manually adding users (students, teachers, other admins)
        error_log("api.php: Handling create_user action.");
        if ($authenticatedUser['role'] !== 'admin') {
            error_log("api.php - create_user: Access denied for role " . $authenticatedUser['role']);
            error_response(403, "Access denied. Only Admins can create users.");
        }

        $rawData = file_get_contents("php://input");
        error_log("api.php - Raw POST data for create_user: " . $rawData);
        $data = json_decode($rawData, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("api.php - create_user: JSON Decode Error: " . json_last_error_msg() . " Raw data: " . $rawData);
            error_response(400, "Invalid JSON payload.");
        }
        error_log("api.php - Decoded JSON data: " . print_r($data, true));

        $name = isset($data['name']) ? preg_replace('/\s+/u', ' ', trim($data['name'])) : null;
        $email = isset($data['email']) ? trim($data['email']) : null;
        $password = isset($data['password']) ? $data['password'] : null;
        $role = isset($data['role']) ? trim($data['role']) : 'student';
        $prn = isset($data['prn']) ? trim($data['prn']) : null;
        $department = isset($data['department']) ? trim($data['department']) : null;
        $year = isset($data['year']) ? trim($data['year']) : null;
        $status = 'active'; // Admin created users are typically active directly

        error_log("api.php - Processed data for user creation: Name='" . $name . "', Email='" . $email . "', Role='" . $role . "', PRN='" . $prn . "', Dept='" . $department . "', Year='" . $year . "'");

        // Server-side validation
        if (empty($name) || empty($email) || empty($password) || empty($role)) {
            error_log("api.php - create_user: Missing required fields.");
            error_response(400, "Name, email, password, and role are required.");
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            error_log("api.php - create_user: Invalid email format.");
            error_response(400, "Invalid email format.");
        }
        if (strlen($password) < 6) { // Minimum password length
            error_log("api.php - create_user: Password too short (min 6 characters).");
            error_response(400, "Password must be at least 6 characters long.");
        }
        // PRN is only required for students
        if ($role === 'student' && (empty($prn) || !preg_match('/^[A-Z0-9]+$/i', $prn))) {
            error_log("api.php - create_user: Invalid PRN format for student.");
            error_response(400, "Invalid PRN format for students. Only alphanumeric characters allowed.");
        }
        // Department and Year are only required for students
        if ($role === 'student' && (empty($department) || empty($year))) {
            error_log("api.php - create_user: Missing department or year for student.");
            error_response(400, "Department and year are required for students.");
        }

        // Check for existing PRN or email
        $sql_check_duplicate = "SELECT COUNT(*) FROM users WHERE email = ?" . (($role === 'student' && $prn !== null) ? " OR prn = ?" : "");
        $stmt_check_duplicate = $conn->prepare($sql_check_duplicate);
        if (!$stmt_check_duplicate) {
            error_log("api.php - create_user: Prepare failed for duplicate check: " . $conn->error);
            error_response(500, "Database error during duplicate check preparation.");
        }

        if ($role === 'student' && $prn !== null) {
            $stmt_check_duplicate->bind_param("ss", $email, $prn);
        } else {
            $stmt_check_duplicate->bind_param("s", $email);
        }
        $stmt_check_duplicate->execute();
        $result_check_duplicate = $stmt_check_duplicate->get_result();
        $count_duplicate = $result_check_duplicate->fetch_row()[0];
        $stmt_check_duplicate->close();

        if ($count_duplicate > 0) {
            error_log("api.php - create_user: Email or PRN already exists.");
            error_response(409, "An account with this Email or PRN already exists."); // Conflict
        }

        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        $conn->begin_transaction();
        try {
            $sql_insert = "INSERT INTO users (name, email, password, role, status"; // Changed password_hash to password
            $params = [$name, $email, $hashed_password, $role, $status];
            $types = "sssss";

            if ($role === 'student') {
                $sql_insert .= ", prn, department, year";
                $params[] = $prn;
                $params[] = $department;
                $params[] = $year;
                $types .= "sss";
            }
            $sql_insert .= ") VALUES (" . implode(', ', array_fill(0, count($params), '?')) . ")";

            $stmt_insert = $conn->prepare($sql_insert);
            if (!$stmt_insert) {
                throw new Exception("Prepare failed for user creation: " . $conn->error);
            }
            $stmt_insert->bind_param($types, ...$params);

            if (!$stmt_insert->execute()) {
                throw new Exception("Error executing user creation: " . $stmt_insert->error);
            }
            $new_user_id = $conn->insert_id;
            $stmt_insert->close();
            error_log("api.php - create_user: New user created with ID: " . $new_user_id);

            // If a student is created, create an initial 'pending' transaction for them
            if ($role === 'student') {
                // Get the current fee amount from settings
                $default_amount = get_current_fee_amount($conn);
                $default_status_transaction = 'pending';
                $default_method = 'Admin Created';
                $default_fee_type = 'initial_creation';
                $default_due_date = date('Y-m-d H:i:s', strtotime('+30 days'));

                $sql_transaction_insert = "INSERT INTO transactions (student_id, amount, status, method, timestamp, fee_type, due_date) VALUES (?, ?, ?, ?, NOW(), ?, ?)";
                $stmt_transaction = $conn->prepare($sql_transaction_insert);
                if (!$stmt_transaction) {
                    throw new Exception("Prepare failed for initial student transaction: " . $conn->error);
                }
                $stmt_transaction->bind_param("iissds", $new_user_id, $default_amount, $default_status_transaction, $default_method, $default_fee_type, $default_due_date);

                if (!$stmt_transaction->execute()) {
                    throw new Exception("Error executing initial student transaction: " . $stmt_transaction->error);
                }
                $stmt_transaction->close();
                error_log("api.php - create_user: Initial pending transaction created for new student ID: " . $new_user_id . ", Transaction ID: " . $conn->insert_id);
            }


            $conn->commit();
            echo json_encode(["success" => true, "message" => "User created successfully!", "user_id" => $new_user_id]);

        } catch (Exception $e) {
            $conn->rollback();
            error_log("api.php - create_user: Error during user creation (rolled back): " . $e->getMessage());
            error_response(500, "User creation failed: " . $e->getMessage());
        }
        break;

    case 'update_student_status':
        error_log("api.php: Handling update_student_status action.");
        if ($authenticatedUser['role'] !== 'admin') {
            error_log("api.php - update_student_status: Access denied for role " . $authenticatedUser['role']);
            error_response(403, "Access denied. Admin privileges required to update users.");
        }

        require_once 'includes/email_helper.php';

        $input = json_decode(file_get_contents('php://input'), true);
        $userId = $input['user_id'] ?? 0;
        $status = $input['status'] ?? null; // Only status is relevant for this specific action

        error_log("api.php - update_student_status: Received user_id=" . $userId . ", new status: " . $status);

        if ($userId <= 0 || empty($status)) {
            error_response(400, "User ID and status are required for update.");
        }

        // Validate status value to prevent arbitrary inputs
        $allowedStatuses = ['active', 'pending', 'denied'];
        if (!in_array($status, $allowedStatuses)) {
            error_response(400, "Invalid status value provided.");
        }

        $conn->begin_transaction();
        try {
            // First get the student's details for email
            $stmt_user = $conn->prepare("SELECT name, email FROM users WHERE user_id = ?");
            if (!$stmt_user) {
                throw new Exception("Failed to prepare statement for getting user details: " . $conn->error);
            }
            $stmt_user->bind_param("i", $userId);
            $stmt_user->execute();
            $user_result = $stmt_user->get_result();
            $user_data = $user_result->fetch_assoc();
            $stmt_user->close();

            if (!$user_data) {
                throw new Exception("User not found");
            }

            $stmt = $conn->prepare("UPDATE users SET status = ? WHERE user_id = ?");
            if (!$stmt) {
                throw new Exception("Failed to prepare statement for update_student_status: " . $conn->error);
            }
            $stmt->bind_param("si", $status, $userId);

            if (!$stmt->execute()) {
                throw new Exception("Failed to update user status: " . $stmt->error);
            }
            $stmt->close();

            // If student status is updated to 'denied', cancel any pending transactions
            if ($status === 'denied') {
                $sql_cancel_transactions = "UPDATE transactions SET status = 'cancelled' WHERE student_id = ? AND status = 'pending'";
                $stmt_cancel = $conn->prepare($sql_cancel_transactions);
                if (!$stmt_cancel) {
                    error_log("api.php - update_student_status: Prepare failed for canceling transactions: " . $conn->error);
                    // Log the error but don't halt the user status update if this specific part fails
                } else {
                    $stmt_cancel->bind_param("i", $userId);
                    $stmt_cancel->execute();
                    error_log("api.php - update_student_status: Canceled pending transactions for denied user ID: " . $userId);
                    $stmt_cancel->close();
                }
            }

            // Send email notification if status is changed to 'active'
            if ($status === 'active') {
                $emailSent = sendRegistrationApprovalEmail($user_data['email'], $user_data['name']);
                if (!$emailSent) {
                    // Log the error but don't halt the transaction
                    error_log("api.php - update_student_status: Failed to send approval email to: " . $user_data['email']);
                }
            }

            $conn->commit();
            echo json_encode(['message' => 'Student status updated successfully']);

        } catch (Exception $e) {
            $conn->rollback();
            error_log("api.php - update_student_status: Error during status update (rolled back): " . $e->getMessage());
            error_response(500, "Failed to update student status: " . $e->getMessage());
        }
        break;


    case 'update_user':
        error_log("api.php: Handling update_user action.");
        if ($authenticatedUser['role'] !== 'admin') {
            error_log("api.php - update_user: Access denied for role " . $authenticatedUser['role']);
            error_response(403, "Access denied. Admin privileges required to update users.");
        }

        $input = json_decode(file_get_contents('php://input'), true);
        $userId = $input['user_id'] ?? 0;
        $name = $input['name'] ?? null;
        $email = $input['email'] ?? null;
        $role = $input['role'] ?? null;
        $status = $input['status'] ?? null;
        $password = $input['password'] ?? null; // Optional password update
        $prn = $input['prn'] ?? null;
        $department = $input['department'] ?? null;
        $year = $input['year'] ?? null;

        error_log("api.php - update_user: Received user_id=" . $userId . ", data: " . print_r($input, true));

        if ($userId <= 0) {
            error_response(400, "User ID is required and must be a positive integer.");
        }

        $updates = [];
        $params = [];
        $types = "";

        if ($name !== null) { $updates[] = "name = ?"; $params[] = trim($name); $types .= "s"; }
        if ($email !== null) {
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                error_response(400, "Invalid email format.");
            }
            $updates[] = "email = ?"; $params[] = trim($email); $types .= "s";
        }
        if ($role !== null) { $updates[] = "role = ?"; $params[] = trim($role); $types .= "s"; }
        if ($status !== null) { $updates[] = "status = ?"; $params[] = trim($status); $types .= "s"; }
        if ($password !== null) {
            if (strlen($password) < 6) {
                error_response(400, "Password must be at least 6 characters long.");
            }
            $password_hash = password_hash($password, PASSWORD_DEFAULT);
            $updates[] = "password = ?"; $params[] = $password_hash; $types .= "s"; // Changed password_hash to password
        }
        if ($prn !== null) {
            if (!preg_match('/^[A-Z0-9]+$/i', $prn)) {
                error_response(400, "Invalid PRN format. Only alphanumeric characters allowed.");
            }
            $updates[] = "prn = ?"; $params[] = trim($prn); $types .= "s";
        } else {
             $updates[] = "prn = NULL"; // Explicitly set to NULL if provided as empty
        }
        if ($department !== null) { $updates[] = "department = ?"; $params[] = trim($department); $types .= "s"; } else { $updates[] = "department = NULL"; } // Explicitly set to NULL
        if ($year !== null) { $updates[] = "year = ?"; $params[] = trim($year); $types .= "s"; } else { $updates[] = "year = NULL"; } // Explicitly set to NULL


        if (empty($updates)) {
            error_response(400, "No fields provided for update.");
        }

        // Check for duplicate email/prn if they are being updated
        if ($email !== null || $prn !== null) {
            $sql_check_duplicate = "SELECT COUNT(*) FROM users WHERE (email = ?" . (($prn !== null) ? " OR prn = ?" : "") . ") AND user_id != ?";
            $stmt_check_duplicate = $conn->prepare($sql_check_duplicate);
            if (!$stmt_check_duplicate) {
                error_log("api.php - update_user: Prepare failed for duplicate check: " . $conn->error);
                error_response(500, "Database error during duplicate check preparation.");
            }
            if ($prn !== null) {
                $stmt_check_duplicate->bind_param("ssi", $email, $prn, $userId);
            } else {
                $stmt_check_duplicate->bind_param("si", $email, $userId);
            }
            $stmt_check_duplicate->execute();
            $result_check_duplicate = $stmt_check_duplicate->get_result();
            $count_duplicate = $result_check_duplicate->fetch_row()[0];
            $stmt_check_duplicate->close();

            if ($count_duplicate > 0) {
                error_log("api.php - update_user: Email or PRN already exists for another user.");
                error_response(409, "An account with this Email or PRN already exists."); // Conflict
            }
        }


        $stmt = $conn->prepare("UPDATE users SET " . implode(', ', $updates) . " WHERE user_id = ?");
        if (!$stmt) {
            error_response(500, "Failed to prepare statement for update_user: " . $conn->error);
        }

        $params[] = $userId;
        $types .= "i"; // 'i' for integer user_id

        $stmt->bind_param($types, ...$params);

        if ($stmt->execute()) {
            // If student status is updated to 'denied', cancel any pending transactions
            if ($status === 'denied') {
                $sql_cancel_transactions = "UPDATE transactions SET status = 'cancelled' WHERE student_id = ? AND status = 'pending'";
                $stmt_cancel = $conn->prepare($sql_cancel_transactions);
                if (!$stmt_cancel) {
                    error_log("api.php - update_user: Prepare failed for canceling transactions: " . $conn->error);
                    // Do not exit, just log and continue if this specific part fails
                } else {
                    $stmt_cancel->bind_param("i", $userId);
                    $stmt_cancel->execute();
                    error_log("api.php - update_user: Canceled pending transactions for denied user ID: " . $userId);
                    $stmt_cancel->close();
                }
            }
            echo json_encode(['message' => 'User updated successfully']);
        } else {
            error_response(500, 'Failed to update user: ' . $stmt->error);
        }
        $stmt->close(); // Close statement for update_user
        break;

    case 'delete_user':
        error_log("api.php: Handling delete_user action.");
        if ($authenticatedUser['role'] !== 'admin') {
            error_log("api.php - delete_user: Access denied for role " . $authenticatedUser['role']);
            error_response(403, "Access denied. Admin privileges required to delete users.");
        }

        $userId = $_GET['user_id'] ?? 0;

        if ($userId <= 0) {
            error_response(400, "User ID is required and must be a positive integer.");
        }

        $conn->begin_transaction();
        try {
            // Delete related transactions first (or set to cascade delete in DB schema)
            $stmt_delete_transactions = $conn->prepare("DELETE FROM transactions WHERE student_id = ?");
            if (!$stmt_delete_transactions) {
                throw new Exception("Failed to prepare statement for deleting transactions: " . $conn->error);
            }
            $stmt_delete_transactions->bind_param("i", $userId);
            if (!$stmt_delete_transactions->execute()) {
                throw new Exception("Failed to delete user's transactions: " . $stmt_delete_transactions->error);
            }
            $stmt_delete_transactions->close();
            error_log("api.php - delete_user: Deleted transactions for user ID: " . $userId);

            // Then delete the user
            $stmt_delete_user = $conn->prepare("DELETE FROM users WHERE user_id = ?");
            if (!$stmt_delete_user) {
                throw new Exception("Failed to prepare statement for deleting user: " . $conn->error);
            }
            $stmt_delete_user->bind_param("i", $userId);

            if ($stmt_delete_user->execute()) {
                $conn->commit();
                error_log("api.php - delete_user: User ID " . $userId . " deleted successfully.");
                echo json_encode(['message' => 'User deleted successfully']);
            } else {
                throw new Exception("Failed to delete user: " . $stmt_delete_user->error);
            }
            $stmt_delete_user->close(); // Close statement for delete_user
        } catch (Exception $e) {
            $conn->rollback();
            error_log("api.php - delete_user: Error during user deletion (rolled back): " . $e->getMessage());
            error_response(500, "Failed to delete user: " . $e->getMessage());
        }
        break;

    case 'get_user':
        error_log("api.php: Handling get_user action.");
        // Admin can get any user; regular user can only get their own info
        $requested_user_id = $_GET['user_id'] ?? null;
        if (empty($requested_user_id)) {
            error_response(400, "User ID is required.");
        }

        if ($authenticatedUser['role'] !== 'admin' && $authenticatedUser['user_id'] != $requested_user_id) {
             error_response(403, "Access denied. You can only view your own profile, or be an admin to view others.");
        }

        try {
            $stmt = $conn->prepare("SELECT user_id, name, email, role, status, prn, department, year FROM users WHERE user_id = ?");
            if (!$stmt) {
                error_response(500, "Failed to prepare statement for get_user: " . $conn->error);
            }
            $stmt->bind_param("i", $requested_user_id);
            $stmt->execute();
            $result = $stmt->get_result();
            $user = $result->fetch_assoc();
            $stmt->close();

            if ($user) {
                echo json_encode($user);
            } else {
                error_response(404, "User not found.");
            }
        } catch (Exception $e) {
            error_log("api.php - get_user: Error: " . $e->getMessage());
            error_response(500, "Database error: " . $e->getMessage());
        }
        break;

    case 'get_fund_balance':
        error_log("api.php: Handling get_fund_balance action.");
        if ($authenticatedUser['role'] !== 'admin' && $authenticatedUser['role'] !== 'teacher') { // Assuming teacher also has access to this
            error_response(403, "Access denied. Admin or Teacher privileges required.");
        }
        try {
            // Calculate total collected fees from transactions table
            $stmt_collected = $conn->prepare("SELECT SUM(amount) AS total_collected FROM transactions WHERE status = 'paid'");
            if (!$stmt_collected) {
                error_response(500, "Failed to prepare statement (collected funds): " . $conn->error);
            }
            $stmt_collected->execute();
            $result_collected = $stmt_collected->get_result();
            $totalCollected = $result_collected->fetch_assoc()['total_collected'] ?? 0;
            $stmt_collected->close();

            // Calculate total event costs from events table
            $stmt_spent = $conn->prepare("SELECT SUM(total_cost) AS total_spent FROM events WHERE event_type = 'conducted'"); // Assuming 'conducted' events represent expenditures
            if (!$stmt_spent) {
                error_response(500, "Failed to prepare statement (spent funds): " . $conn->error);
            }
            $stmt_spent->execute();
            $result_spent = $stmt_spent->get_result();
            $totalSpent = $result_spent->fetch_assoc()['total_spent'] ?? 0;
            $stmt_spent->close();

            $balance = $totalCollected - $totalSpent;

            echo json_encode([
                'total_collected' => (float)$totalCollected,
                'total_spent' => (float)$totalSpent,
                'total_balance' => (float)$balance // Changed key to 'total_balance' for consistency with frontend
            ]);
        } catch (Exception $e) {
            error_log("api.php - get_fund_balance: Error: " . $e->getMessage());
            error_response(500, "Database error: " . $e->getMessage());
        }
        break;

    case 'get_student_fee_status':
        error_log("api.php: Handling get_student_fee_status action.");
        if ($authenticatedUser['role'] !== 'admin' && $authenticatedUser['role'] !== 'teacher') {
            error_response(403, "Access denied. Admin or Teacher privileges required.");
        }
        try {
            // Get data for students with pending or paid transactions
            $stmt_student_fees = $conn->prepare("
                SELECT u.user_id, u.name AS student_name, u.prn, u.department, u.year, u.status AS user_status,
                       COALESCE(SUM(CASE WHEN t.status = 'paid' THEN t.amount ELSE 0 END), 0) AS total_paid_amount,
                       COALESCE(SUM(CASE WHEN t.status = 'pending' THEN t.amount ELSE 0 END), 0) AS total_pending_amount
                FROM users u
                LEFT JOIN transactions t ON u.user_id = t.student_id
                WHERE u.role = 'student'
                GROUP BY u.user_id, u.name, u.prn, u.department, u.year, u.status
                ORDER BY u.name ASC
            ");
            if (!$stmt_student_fees) {
                error_response(500, "Failed to prepare statement (student fee status): " . $conn->error);
            }
            $stmt_student_fees->execute();
            $result_student_fees = $stmt_student_fees->get_result();
            $studentsFeeDetails = $result_student_fees->fetch_all(MYSQLI_ASSOC);
            $stmt_student_fees->close();

            // Count for badge/summary
            $studentsWithPendingFeesCount = 0;
            $totalActiveStudentsCount = 0; // Only count active students

            foreach ($studentsFeeDetails as $student) {
                if ($student['user_status'] === 'active') { // Only count active students
                    $totalActiveStudentsCount++;
                    if ($student['total_pending_amount'] > 0) {
                        $studentsWithPendingFeesCount++;
                    }
                }
            }

            echo json_encode([
                'students_with_pending_fees' => (int)$studentsWithPendingFeesCount,
                'total_active_students' => (int)$totalActiveStudentsCount,
                'pending_students_details' => $studentsFeeDetails // All relevant student fee data
            ]);
        } catch (Exception $e) {
            error_log("api.php - get_student_fee_status: Error: " . $e->getMessage());
            error_response(500, "Database error: " . $e->getMessage());
        }
        break;

    // --- Teacher/Admin Actions (Events) ---
    case 'get_events':
        error_log("api.php: Handling get_events action.");
       if ($authenticatedUser['role'] !== 'teacher' && $authenticatedUser['role'] !== 'admin' && $authenticatedUser['role'] !== 'student') {
            error_response(403, "Access denied. Teacher or Admin privileges required.");
        }
        $stmt = $conn->prepare("SELECT event_id, event_name, event_date, event_type, total_cost FROM events ORDER BY event_date DESC");
        if (!$stmt) {
            error_response(500, "Failed to prepare statement for get_events: " . $conn->error);
        }
        $stmt->execute();
        $result = $stmt->get_result();
        $events = [];
        while ($row = $result->fetch_assoc()) {
            $events[] = $row;
        }
        $stmt->close();
        echo json_encode($events);
        break;

    case 'add_event':
        error_log("api.php: Handling add_event action.");
        if ($authenticatedUser['role'] !== 'teacher' && $authenticatedUser['role'] !== 'admin') {
            error_response(403, "Access denied. Teacher or Admin privileges required.");
        }
        $input = json_decode(file_get_contents('php://input'), true);
        $eventName = $input['event_name'] ?? '';
        $eventDate = $input['event_date'] ?? '';
        $eventType = $input['event_type'] ?? '';
        $totalCost = $input['total_cost'] ?? 0.00;

        if (empty($eventName) || empty($eventDate) || empty($eventType)) {
            error_response(400, 'Event name, date, and type are required');
        }

        $stmt = $conn->prepare("INSERT INTO events (event_name, event_date, event_type, total_cost) VALUES (?, ?, ?, ?)");
        if (!$stmt) {
            error_response(500, "Failed to prepare statement for add_event: " . $conn->error);
        }
        $stmt->bind_param("sssd", $eventName, $eventDate, $eventType, $totalCost);

        if ($stmt->execute()) {
            echo json_encode(['message' => 'Event added successfully', 'event_id' => $conn->insert_id]);
        } else {
            error_response(500, 'Failed to add event: ' . $stmt->error);
        }
        $stmt->close();
        break;

    case 'delete_event':
        error_log("api.php: Handling delete_event action.");
        if ($authenticatedUser['role'] !== 'teacher' && $authenticatedUser['role'] !== 'admin') {
            error_response(403, "Access denied. Teacher or Admin privileges required.");
        }
        $eventId = $_GET['event_id'] ?? 0;

        if ($eventId <= 0) {
            error_response(400, 'Event ID is required and must be a positive integer');
        }

        $stmt = $conn->prepare("DELETE FROM events WHERE event_id = ?");
        if (!$stmt) {
            error_response(500, "Failed to prepare statement for delete_event: " . $conn->error);
        }
        $stmt->bind_param("i", $eventId);

        if ($stmt->execute()) {
            echo json_encode(['message' => 'Event deleted successfully']);
        } else {
            error_response(500, 'Failed to delete event: ' . $stmt->error);
        }
        $stmt->close();
        break;

    // --- Teacher/Admin Actions (Transactions) ---
    case 'get_all_fees': // Teachers and Admins can see all transactions
        error_log("api.php: Handling get_all_fees action (now get_all_transactions).");
        if ($authenticatedUser['role'] !== 'teacher' && $authenticatedUser['role'] !== 'admin') {
            error_response(403, "Access denied. Teacher or Admin privileges required.");
        }
        // Assuming 'fees' are represented by 'amount' in 'transactions' table
        $stmt = $conn->prepare("
            SELECT
                t.transaction_id,
                u.name AS student_name,
                u.prn,
                t.amount,
                t.status,
                t.method,
                t.timestamp,
                u.department,
                u.year,
                t.fee_type,
                t.due_date,
                t.upi_transaction_id,
                t.payment_screenshot,
                t.payment_date,
                t.rejection_reason
            FROM
                transactions t
            JOIN
                users u ON t.student_id = u.user_id
             WHERE
                u.status = 'active'
            ORDER BY
                t.timestamp DESC
        ");
        if (!$stmt) {
            error_response(500, "Failed to prepare statement for get_all_fees: " . $conn->error);
        }
        $stmt->execute();
        $result = $stmt->get_result();
        $transactions = [];
        while ($row = $result->fetch_assoc()) {
            $transactions[] = $row;
        }
        $stmt->close();
        echo json_encode($transactions);
        break;

    case 'mark_paid':
        error_log("api.php: Handling mark_paid action.");
        if ($authenticatedUser['role'] !== 'teacher' && $authenticatedUser['role'] !== 'admin') {
            error_response(403, "Access denied. Teacher or Admin privileges required.");
        }
        $data = json_decode(file_get_contents("php://input"), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("api.php - mark_paid: JSON Decode Error: " . json_last_error_msg());
            error_response(400, "Invalid JSON payload for mark_paid.");
        }
        $transaction_id = isset($data['transaction_id']) ? intval($data['transaction_id']) : 0;
        $method = isset($data['method']) ? trim($data['method']) : 'Manual'; // Default method

        error_log("api.php - mark_paid: Received transaction_id=" . $transaction_id . ", method='" . $method . "'");

        if ($transaction_id <= 0) {
            error_response(400, "Transaction ID is required.");
        }

        // Fetch the current transaction status
        $stmt_fetch = $conn->prepare("SELECT status FROM transactions WHERE transaction_id = ?");
        if (!$stmt_fetch) {
            error_response(500, "Failed to prepare statement (fetch transaction status): " . $conn->error);
        }
        $stmt_fetch->bind_param("i", $transaction_id);
        $stmt_fetch->execute();
        $result_fetch = $stmt_fetch->get_result();
        if ($result_fetch->num_rows === 0) {
            $stmt_fetch->close();
            error_response(404, "Transaction not found.");
        }
        $transaction = $result_fetch->fetch_assoc();
        $stmt_fetch->close();

        if ($transaction['status'] === 'paid') {
            error_response(409, 'Transaction is already marked as paid.');
        }

        $conn->begin_transaction();
        try {
            $stmt = $conn->prepare("UPDATE transactions SET status = 'paid', method = ?, timestamp = NOW() WHERE transaction_id = ?");
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }
            $stmt->bind_param("si", $method, $transaction_id);

            if (!$stmt->execute()) {
                throw new Exception("Failed to mark transaction as paid: " . $stmt->error);
            }
            $stmt->close();

            $conn->commit();
            echo json_encode(['message' => 'Payment marked as paid successfully']);
        } catch (Exception $e) {
            $conn->rollback();
            error_log("api.php - mark_paid: Error marking transaction paid (rolled back): " . $e->getMessage());
            error_response(500, "Failed to mark transaction as paid: " . $e->getMessage());
        }
        break;

    // --- Student Actions ---
    case 'get_transactions': // Students can only see their own transactions
        error_log("api.php: Handling get_transactions action (student).");
        // No explicit role check here, as authenticate_token already handles basic authentication.
        // The query itself will filter by student_id.
        if (!$authenticatedUser) { // This check is mostly redundant if authenticate_token exits on failure
             error_response(401, 'Authentication required to view transactions.');
        }

        $student_id = $authenticatedUser['user_id'];

        $stmt = $conn->prepare("
            SELECT
                transaction_id,
                amount,
                status,
                method,
                timestamp,
                fee_type,
                due_date,
                rejection_reason,
                payment_date,
                upi_transaction_id
            FROM
                transactions
            WHERE
                student_id = ?
            ORDER BY
                timestamp DESC
        ");
        if (!$stmt) {
            error_response(500, "Failed to prepare statement for get_transactions: " . $conn->error);
        }
        $stmt->bind_param("i", $student_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $transactions = [];
        while ($row = $result->fetch_assoc()) {
            $row['method'] = $row['method'] === null ? '' : $row['method']; // Ensure method is always a string
            $transactions[] = $row;
        }
        $stmt->close();
        echo json_encode($transactions);
        break;

    case 'submit_payment':
        error_log("api.php: Handling submit_payment action.");
        if (!$authenticatedUser) {
            error_response(401, 'Authentication required to submit payment.');
        }

        // Verify the user is a student
        if ($authenticatedUser['role'] !== 'student') {
            error_response(403, 'Only students can submit payments.');
        }

        // Get the transaction ID and verify it belongs to the student
        $transaction_id = isset($_POST['transaction_id']) ? intval($_POST['transaction_id']) : 0;
        $upi_transaction_id = isset($_POST['upi_transaction_id']) ? trim($_POST['upi_transaction_id']) : '';
        $payment_date = isset($_POST['payment_date']) ? trim($_POST['payment_date']) : '';

        if ($transaction_id <= 0 || empty($upi_transaction_id) || empty($payment_date)) {
            error_response(400, 'Missing required payment information.');
        }

        // Handle file upload
        $screenshot_path = '';
        if (isset($_FILES['payment_screenshot']) && $_FILES['payment_screenshot']['error'] === UPLOAD_ERR_OK) {
            $upload_dir = 'uploads/';
            if (!file_exists($upload_dir)) {
                mkdir($upload_dir, 0777, true);
            }

            $file_extension = strtolower(pathinfo($_FILES['payment_screenshot']['name'], PATHINFO_EXTENSION));
            $allowed_extensions = array('jpg', 'jpeg', 'png');
            
            if (!in_array($file_extension, $allowed_extensions)) {
                error_response(400, 'Invalid file type. Only JPG, JPEG, and PNG files are allowed.');
            }

            $screenshot_path = uniqid('payment_') . '.' . $file_extension;
            $target_path = $upload_dir . $screenshot_path;

            if (!move_uploaded_file($_FILES['payment_screenshot']['tmp_name'], $target_path)) {
                error_response(500, 'Failed to upload payment screenshot.');
            }
        } else {
            error_response(400, 'Payment screenshot is required.');
        }

        try {
            // Verify transaction belongs to student and is pending
            $stmt = $conn->prepare("
                SELECT status 
                FROM transactions 
                WHERE transaction_id = ? AND student_id = ? AND status = 'pending'
            ");
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }
            $stmt->bind_param("ii", $transaction_id, $authenticatedUser['user_id']);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 0) {
                throw new Exception("Invalid transaction or payment already submitted.");
            }
            $stmt->close();

            // Update transaction with payment details
            $stmt = $conn->prepare("
                UPDATE transactions 
                SET upi_transaction_id = ?,
                    payment_screenshot = ?,
                    payment_date = ?,
                    method = 'UPI'
                WHERE transaction_id = ?
            ");
            if (!$stmt) {
                throw new Exception("Failed to prepare update statement: " . $conn->error);
            }
            $stmt->bind_param("sssi", $upi_transaction_id, $screenshot_path, $payment_date, $transaction_id);
            
            if (!$stmt->execute()) {
                throw new Exception("Failed to update transaction: " . $stmt->error);
            }
            $stmt->close();

            echo json_encode(['message' => 'Payment details submitted successfully. Awaiting teacher approval.']);
        } catch (Exception $e) {
            error_response(500, $e->getMessage());
        }
        break;

    case 'get_transaction_details':
        error_log("api.php: Handling get_transaction_details action.");
        if ($authenticatedUser['role'] !== 'teacher' && $authenticatedUser['role'] !== 'admin') {
            error_response(403, "Access denied. Teacher or Admin privileges required.");
        }

        $transaction_id = isset($_GET['transaction_id']) ? intval($_GET['transaction_id']) : 0;
        if ($transaction_id <= 0) {
            error_response(400, "Invalid transaction ID.");
        }

        try {
            $stmt = $conn->prepare("
                SELECT t.*, u.name as student_name
                FROM transactions t
                JOIN users u ON t.student_id = u.user_id
                WHERE t.transaction_id = ?
            ");
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }
            $stmt->bind_param("i", $transaction_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 0) {
                error_response(404, "Transaction not found.");
            }
            
            $transaction = $result->fetch_assoc();
            $stmt->close();
            
            echo json_encode($transaction);
        } catch (Exception $e) {
            error_response(500, $e->getMessage());
        }
        break;

    case 'approve_payment':
        error_log("api.php: Handling approve_payment action.");
        if ($authenticatedUser['role'] !== 'teacher' && $authenticatedUser['role'] !== 'admin') {
            error_response(403, "Access denied. Teacher or Admin privileges required.");
        }

        $data = json_decode(file_get_contents("php://input"), true);
        $transaction_id = isset($data['transaction_id']) ? intval($data['transaction_id']) : 0;

        if ($transaction_id <= 0) {
            error_response(400, "Invalid transaction ID.");
        }

        try {
            $stmt = $conn->prepare("UPDATE transactions SET status = 'paid' WHERE transaction_id = ?");
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }
            $stmt->bind_param("i", $transaction_id);
            
            if (!$stmt->execute()) {
                throw new Exception("Failed to approve payment: " . $stmt->error);
            }
            $stmt->close();
            
            echo json_encode(['message' => 'Payment approved successfully']);
        } catch (Exception $e) {
            error_response(500, $e->getMessage());
        }
        break;

    case 'reject_payment':
        error_log("api.php: Handling reject_payment action.");
        if ($authenticatedUser['role'] !== 'teacher' && $authenticatedUser['role'] !== 'admin') {
            error_response(403, "Access denied. Teacher or Admin privileges required.");
        }

        $data = json_decode(file_get_contents("php://input"), true);
        $transaction_id = isset($data['transaction_id']) ? intval($data['transaction_id']) : 0;
        $rejection_reason = isset($data['rejection_reason']) ? trim($data['rejection_reason']) : '';

        if ($transaction_id <= 0) {
            error_response(400, "Invalid transaction ID.");
        }

        if (empty($rejection_reason)) {
            error_response(400, "Rejection reason is required.");
        }

        try {
            $stmt = $conn->prepare("UPDATE transactions SET status = 'rejected', rejection_reason = ? WHERE transaction_id = ?");
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }
            $stmt->bind_param("si", $rejection_reason, $transaction_id);
            
            if (!$stmt->execute()) {
                throw new Exception("Failed to reject payment: " . $stmt->error);
            }
            $stmt->close();
            
            echo json_encode(['message' => 'Payment rejected successfully']);
        } catch (Exception $e) {
            error_response(500, $e->getMessage());
        }
        break;

    case 'generate_receipt':
        error_log("api.php: Handling generate_receipt action.");
        
        // Check if user is authorized to generate receipt
        if (!$authenticatedUser) {
            error_response(401, "Authentication required to generate receipt.");
        }

        $transaction_id = isset($_GET['transaction_id']) ? intval($_GET['transaction_id']) : 0;
        if ($transaction_id <= 0) {
            error_response(400, "Invalid transaction ID.");
        }

        try {
            // Get transaction details with student information
            $stmt = $conn->prepare("
                SELECT t.*, u.name as student_name, u.prn, u.department, u.year, u.email
                FROM transactions t
                JOIN users u ON t.student_id = u.user_id
                WHERE t.transaction_id = ? AND t.status = 'paid'
                AND (t.student_id = ? OR ? IN ('teacher', 'admin'))
            ");
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }

            $stmt->bind_param("iii", $transaction_id, $authenticatedUser['user_id'], $authenticatedUser['role']);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 0) {
                error_response(404, "Transaction not found or not approved yet.");
            }
            
            $transaction = $result->fetch_assoc();
            $stmt->close();

            // Generate receipt number (format: YEAR/MONTH/TRANSACTION_ID)
            $receipt_number = date('Y') . '/' . date('m') . '/' . str_pad($transaction_id, 4, '0', STR_PAD_LEFT);

            // Convert amount to words
            function numberToWords($number) {
                $ones = array(
                    0 => "", 1 => "One", 2 => "Two", 3 => "Three", 4 => "Four",
                    5 => "Five", 6 => "Six", 7 => "Seven", 8 => "Eight", 9 => "Nine",
                    10 => "Ten", 11 => "Eleven", 12 => "Twelve", 13 => "Thirteen",
                    14 => "Fourteen", 15 => "Fifteen", 16 => "Sixteen", 17 => "Seventeen",
                    18 => "Eighteen", 19 => "Nineteen"
                );
                $tens = array(
                    0 => "", 2 => "Twenty", 3 => "Thirty", 4 => "Forty", 5 => "Fifty",
                    6 => "Sixty", 7 => "Seventy", 8 => "Eighty", 9 => "Ninety"
                );
                $hundreds = array(
                    "Hundred", "Thousand", "Lakh", "Crore"
                );

                if ($number == 0) return "Zero";

                $words = "";
                
                // Handle crores
                $crore = floor($number / 10000000);
                if ($crore > 0) {
                    $words .= numberToWords($crore) . " Crore ";
                    $number = $number % 10000000;
                }
                
                // Handle lakhs
                $lakh = floor($number / 100000);
                if ($lakh > 0) {
                    $words .= numberToWords($lakh) . " Lakh ";
                    $number = $number % 100000;
                }
                
                // Handle thousands
                $thousand = floor($number / 1000);
                if ($thousand > 0) {
                    $words .= numberToWords($thousand) . " Thousand ";
                    $number = $number % 1000;
                }
                
                // Handle hundreds
                $hundred = floor($number / 100);
                if ($hundred > 0) {
                    $words .= numberToWords($hundred) . " Hundred ";
                    $number = $number % 100;
                }
                
                if ($number > 0) {
                    if ($words != "") $words .= "and ";
                    if ($number < 20) {
                        $words .= $ones[$number];
                    } else {
                        $words .= $tens[floor($number / 10)];
                        if ($number % 10 > 0) {
                            $words .= " " . $ones[$number % 10];
                        }
                    }
                }
                
                return trim($words);
            }

            $amount = floatval($transaction['amount']);
            $rupees = floor($amount);
            $paise = round(($amount - $rupees) * 100);
            $amount_in_words = numberToWords($rupees) . " Rupees";
            if ($paise > 0) {
                $amount_in_words .= " and " . numberToWords($paise) . " Paise";
            }

            // Read the receipt template
            $template = file_get_contents('receipt_template.html');
            
            // Replace placeholders with actual data
            $replacements = [
                '{{receipt_number}}' => $receipt_number,
                '{{receipt_date}}' => date('d-m-Y'),
                '{{student_name}}' => $transaction['student_name'],
                '{{student_email}}' => $transaction['email'],
                '{{prn_number}}' => $transaction['prn'],
                '{{department}}' => $transaction['department'] . ($transaction['year'] ? '/' . $transaction['year'] : ''),
                '{{payment_date}}' => date('d-m-Y', strtotime($transaction['payment_date'])),
                '{{transaction_id}}' => $transaction['upi_transaction_id'],
                '{{payment_method}}' => $transaction['method'],
                '{{amount}}' => number_format($transaction['amount'], 2),
                '{{amount_in_words}}' => $amount_in_words,
                '{{fee_type}}' => ucwords(str_replace('_', ' ', $transaction['fee_type']))
            ];

            $receipt = str_replace(
                array_keys($replacements),
                array_values($replacements),
                $template
            );

            // Set headers for HTML content
            header('Content-Type: text/html');
            header('Content-Disposition: inline; filename="receipt_' . $receipt_number . '.html"');
            
            echo $receipt;
            exit;

        } catch (Exception $e) {
            error_response(500, "Failed to generate receipt: " . $e->getMessage());
        }
        break;

    case 'get_fee_amount':
        error_log("api.php: Handling get_fee_amount action.");
        if ($authenticatedUser['role'] !== 'admin' && $authenticatedUser['role'] !== 'teacher') {
            error_response(403, "Access denied. Admin or Teacher privileges required.");
        }
        try {
            $stmt = $conn->prepare("SELECT fee_amount FROM fee_settings ORDER BY id DESC LIMIT 1");
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result->num_rows === 0) {
                throw new Exception("No fee amount found");
            }
            $fee_amount = $result->fetch_assoc()['fee_amount'];
            $stmt->close();
            echo json_encode(['fee_amount' => (float)$fee_amount]);
        } catch (Exception $e) {
            error_response(500, $e->getMessage());
        }
        break;

    case 'update_fee_amount':
        error_log("api.php: Handling update_fee_amount action.");
        if ($authenticatedUser['role'] !== 'admin' && $authenticatedUser['role'] !== 'teacher') {
            error_response(403, "Access denied. Admin or Teacher privileges required.");
        }
        
        $data = json_decode(file_get_contents("php://input"), true);
        $new_fee_amount = isset($data['fee_amount']) ? floatval($data['fee_amount']) : 0;
        
        if ($new_fee_amount <= 0) {
            error_response(400, "Invalid fee amount. Must be greater than 0.");
        }
        
        try {
            // Start transaction to ensure data consistency
            $conn->begin_transaction();
            
            // Insert new fee setting
            $stmt = $conn->prepare("INSERT INTO fee_settings (fee_amount, updated_by) VALUES (?, ?)");
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }
            $stmt->bind_param("di", $new_fee_amount, $authenticatedUser['user_id']);
            
            if (!$stmt->execute()) {
                throw new Exception("Failed to update fee amount: " . $stmt->error);
            }
            $stmt->close();
            
            // Update all pending transactions with the new fee amount
            $stmt = $conn->prepare("UPDATE transactions SET amount = ? WHERE status = 'pending'");
            if (!$stmt) {
                throw new Exception("Failed to prepare statement for updating pending transactions: " . $conn->error);
            }
            $stmt->bind_param("d", $new_fee_amount);
            
            if (!$stmt->execute()) {
                throw new Exception("Failed to update pending transactions: " . $stmt->error);
            }
            $updated_transactions = $stmt->affected_rows;
            $stmt->close();
            
            // Commit the transaction
            $conn->commit();
            
            $message = "Fee amount updated successfully";
            if ($updated_transactions > 0) {
                $message .= ". Updated {$updated_transactions} pending transaction(s) with new fee amount.";
            }
            
            echo json_encode([
                'message' => $message, 
                'fee_amount' => $new_fee_amount,
                'updated_transactions' => $updated_transactions
            ]);
        } catch (Exception $e) {
            // Rollback on error
            $conn->rollback();
            error_response(500, $e->getMessage());
        }
        break;

    case 'forgot_password':
        error_log("api.php: Handling forgot_password action.");
        $data = json_decode(file_get_contents("php://input"), true);
        $email = $data['email'] ?? '';

        if (empty($email)) {
            error_response(400, "Email address is required.");
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            error_response(400, "Invalid email address format.");
        }

        try {
            // Check if user exists
            $stmt = $conn->prepare("SELECT user_id, name, email FROM users WHERE email = ?");
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 0) {
                // Don't reveal if email exists or not for security
                echo json_encode(['success' => true, 'message' => 'If the email address exists in our system, a password reset link has been sent.']);
                exit();
            }
            
            $user = $result->fetch_assoc();
            $stmt->close();

            // Generate reset token
            $token = bin2hex(random_bytes(32));
            // Use MySQL's NOW() + INTERVAL 1 HOUR for expires_at
            $stmt = $conn->prepare("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, NOW() + INTERVAL 1 HOUR)");
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }
            $stmt->bind_param("is", $user['user_id'], $token);
            if (!$stmt->execute()) {
                throw new Exception("Failed to create reset token: " . $stmt->error);
            }
            $stmt->close();

            // Send email
            require_once 'includes/email_helper.php';
            
            $reset_link = "http://" . $_SERVER['HTTP_HOST'] . dirname($_SERVER['REQUEST_URI']) . "/reset_password.html?token=" . $token;
            
            $subject = "Password Reset Request - " . SYSTEM_NAME;
            $body = "
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; }
                    .container { padding: 20px; }
                    .header { color: #2c3e50; font-size: 24px; margin-bottom: 20px; }
                    .content { line-height: 1.6; color: #333; }
                    .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                    .footer { margin-top: 30px; color: #666; font-size: 14px; }
                    .warning { color: #dc3545; font-weight: bold; }
                </style>
            </head>
            <body>
                <div class='container'>
                    <div class='header'>Password Reset Request</div>
                    <div class='content'>
                        <p>Dear " . htmlspecialchars($user['name']) . ",</p>
                        <p>We received a request to reset your password for your " . SYSTEM_NAME . " account.</p>
                        <p>Click the button below to reset your password:</p>
                        <a href='$reset_link' class='button'>Reset Password</a>
                        <p>Or copy and paste this link into your browser:</p>
                        <p>$reset_link</p>
                        <p class='warning'>This link will expire in 1 hour for security reasons.</p>
                        <p>If you didn't request this password reset, please ignore this email. Your password will remain unchanged.</p>
                    </div>
                    <div class='footer'>
                        <p>Best regards,<br>" . SYSTEM_NAME . " Team</p>
                    </div>
                </div>
            </body>
            </html>
            ";

            if (sendEmail($user['email'], $subject, $body)) {
                echo json_encode(['success' => true, 'message' => 'Password reset link has been sent to your email address. Please check your inbox.']);
            } else {
                throw new Exception("Failed to send password reset email.");
            }

        } catch (Exception $e) {
            error_response(500, "Failed to process password reset request: " . $e->getMessage());
        }
        break;

    case 'reset_password':
        error_log("api.php: Handling reset_password action.");
        $data = json_decode(file_get_contents("php://input"), true);
        $token = $data['token'] ?? '';
        $password = $data['password'] ?? '';

        if (empty($token) || empty($password)) {
            error_response(400, "Token and new password are required.");
        }

        if (strlen($password) < 6) {
            error_response(400, "Password must be at least 6 characters long.");
        }

        try {
            // Find valid reset token
            $stmt = $conn->prepare("
                SELECT prt.*, u.email 
                FROM password_reset_tokens prt 
                JOIN users u ON prt.user_id = u.user_id 
                WHERE prt.token = ? AND prt.expires_at > NOW() AND prt.used = FALSE
            ");
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }
            $stmt->bind_param("s", $token);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 0) {
                error_response(400, "Invalid or expired reset token. Please request a new password reset.");
            }
            
            $reset_token = $result->fetch_assoc();
            $stmt->close();

            // Hash new password
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            // Update user password
            $stmt = $conn->prepare("UPDATE users SET password = ? WHERE user_id = ?");
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }
            $stmt->bind_param("si", $hashed_password, $reset_token['user_id']);
            
            if (!$stmt->execute()) {
                throw new Exception("Failed to update password: " . $stmt->error);
            }
            $stmt->close();

            // Mark token as used
            $stmt = $conn->prepare("UPDATE password_reset_tokens SET used = TRUE WHERE id = ?");
            if (!$stmt) {
                throw new Exception("Failed to mark token as used: " . $conn->error);
            }
            $stmt->bind_param("i", $reset_token['id']);
            $stmt->execute();
            $stmt->close();

            // Send confirmation email
            require_once 'includes/email_helper.php';
            
            $subject = "Password Reset Successful - " . SYSTEM_NAME;
            $body = "
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; }
                    .container { padding: 20px; }
                    .header { color: #2c3e50; font-size: 24px; margin-bottom: 20px; }
                    .content { line-height: 1.6; color: #333; }
                    .footer { margin-top: 30px; color: #666; font-size: 14px; }
                </style>
            </head>
            <body>
                <div class='container'>
                    <div class='header'>Password Reset Successful</div>
                    <div class='content'>
                        <p>Your password has been successfully reset.</p>
                        <p>You can now log in to your account using your new password.</p>
                        <p>If you didn't perform this action, please contact the administration immediately.</p>
                    </div>
                    <div class='footer'>
                        <p>Best regards,<br>" . SYSTEM_NAME . " Team</p>
                    </div>
                </div>
            </body>
            </html>
            ";

            sendEmail($reset_token['email'], $subject, $body);

            echo json_encode(['success' => true, 'message' => 'Password has been reset successfully. You can now login with your new password.']);

        } catch (Exception $e) {
            error_response(500, "Failed to reset password: " . $e->getMessage());
        }
        break;

    default:
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action']);
        break;
}

// Ensure the connection is closed
if ($conn instanceof mysqli) {
    $conn->close();
}

?>