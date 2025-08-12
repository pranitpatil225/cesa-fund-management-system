<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';
require_once 'config.php';

/**
 * Send an email using PHPMailer
 * 
 * @param string $to Recipient email address
 * @param string $subject Email subject
 * @param string $body Email body (HTML)
 * @return bool True if email was sent successfully, false otherwise
 */
function sendEmail($to, $subject, $body) {
    try {
        $mail = new PHPMailer(true);

        // Server settings
        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USERNAME;
        $mail->Password = SMTP_PASSWORD;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = SMTP_PORT;

        // Recipients
        $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        $mail->addAddress($to);

        // Content
        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body = $body;

        $mail->send();
        error_log("Email sent successfully to: " . $to);
        return true;
    } catch (Exception $e) {
        error_log("Email sending failed. Error: " . $mail->ErrorInfo);
        return false;
    }
}

/**
 * Send registration approval email to student
 * 
 * @param string $studentEmail Student's email address
 * @param string $studentName Student's name
 * @return bool True if email was sent successfully, false otherwise
 */
function sendRegistrationApprovalEmail($studentEmail, $studentName) {
    $subject = "Registration Approved - " . SYSTEM_NAME;
    
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
            <div class='header'>Registration Approved!</div>
            <div class='content'>
                <p>Dear $studentName,</p>
                <p>We are pleased to inform you that your registration for the " . SYSTEM_NAME . " has been approved by the HOD.</p>
                <p>You can now log in to your account using your registered email/PRN and password.</p>
                <p>If you have any questions or need assistance, please don't hesitate to contact the administration at " . ADMIN_EMAIL . ".</p>
            </div>
            <div class='footer'>
                <p>Best regards,<br>" . SYSTEM_NAME . " Team</p>
            </div>
        </div>
    </body>
    </html>
    ";

    return sendEmail($studentEmail, $subject, $body);
} 