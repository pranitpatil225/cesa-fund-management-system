<?php
// Test script to verify payment approval functionality
require_once 'db_connect.php';

echo "<h2>Payment Approval Test</h2>";

// Check current transaction statuses
echo "<h3>Current Transaction Statuses:</h3>";
$result = $conn->query("SELECT transaction_id, student_id, status, upi_transaction_id, payment_screenshot, payment_date FROM transactions ORDER BY transaction_id LIMIT 5");
echo "<table border='1' style='border-collapse: collapse;'>";
echo "<tr><th>ID</th><th>Student ID</th><th>Status</th><th>UPI ID</th><th>Screenshot</th><th>Payment Date</th></tr>";
while ($row = $result->fetch_assoc()) {
    echo "<tr>";
    echo "<td>" . $row['transaction_id'] . "</td>";
    echo "<td>" . $row['student_id'] . "</td>";
    echo "<td>" . ($row['status'] ?: 'EMPTY') . "</td>";
    echo "<td>" . ($row['upi_transaction_id'] ?: 'NULL') . "</td>";
    echo "<td>" . ($row['payment_screenshot'] ?: 'NULL') . "</td>";
    echo "<td>" . ($row['payment_date'] ?: 'NULL') . "</td>";
    echo "</tr>";
}
echo "</table>";

// Test approval process
echo "<h3>Testing Approval Process:</h3>";

// Find a transaction with payment details but pending status
$result = $conn->query("SELECT transaction_id FROM transactions WHERE status = 'pending' AND upi_transaction_id IS NOT NULL AND payment_screenshot IS NOT NULL LIMIT 1");
if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    $transaction_id = $row['transaction_id'];
    
    echo "Found transaction ID: $transaction_id to test approval<br>";
    
    // Simulate approval
    $stmt = $conn->prepare("UPDATE transactions SET status = 'paid' WHERE transaction_id = ?");
    $stmt->bind_param("i", $transaction_id);
    
    if ($stmt->execute()) {
        echo "✅ Successfully approved transaction $transaction_id<br>";
        
        // Verify the change
        $check = $conn->query("SELECT status FROM transactions WHERE transaction_id = $transaction_id");
        $status = $check->fetch_assoc()['status'];
        echo "New status: $status<br>";
    } else {
        echo "❌ Failed to approve transaction<br>";
    }
    $stmt->close();
} else {
    echo "No suitable transaction found for testing approval<br>";
}

// Show final status counts
echo "<h3>Final Status Counts:</h3>";
$result = $conn->query("SELECT status, COUNT(*) as count FROM transactions GROUP BY status");
echo "<table border='1' style='border-collapse: collapse;'>";
echo "<tr><th>Status</th><th>Count</th></tr>";
while ($row = $result->fetch_assoc()) {
    echo "<tr>";
    echo "<td>" . ($row['status'] ?: 'EMPTY') . "</td>";
    echo "<td>" . $row['count'] . "</td>";
    echo "</tr>";
}
echo "</table>";

echo "<h3>Test Complete!</h3>";
echo "<p>If you see 'paid' transactions in the count above, the approval system is working correctly.</p>";
?> 