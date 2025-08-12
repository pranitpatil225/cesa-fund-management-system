# 🎓 CESA Fund Management System

[![PHP](https://img.shields.io/badge/PHP-8.0+-777BB4?style=for-the-badge&logo=php&logoColor=white)](https://php.net)
[![MySQL](https://img.shields.io/badge/MySQL-8.0+-4479A1?style=for-the-badge&logo=mysql&logoColor=white)](https://mysql.com)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3.0-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white)](https://getbootstrap.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

A comprehensive, production-ready web application for managing student funds, events, and administrative tasks for educational institutions. Built with modern web technologies and enterprise-grade security.

## 🌟 Live Demo

**🔗 Demo URL**: [Coming Soon - Deploy to see it live!]

**👥 Demo Accounts**:
- **Admin**: `admin@cesa.com` / `admin123`
- **Teacher**: `teacher@cesa.com` / `teacher123`
- **Student**: `student@cesa.com` / `student123`

## ✨ Features

### 🎯 **Multi-Role Access Control**
- **👨‍🎓 Students**: Payment tracking, event participation, receipt generation
- **👨‍🏫 Teachers**: Event management, student monitoring, financial reports
- **👨‍💼 Administrators**: User management, bulk operations, system configuration

### 💰 **Financial Management**
- Multiple payment methods (Online, Cash, UPI)
- Real-time transaction tracking
- Automated receipt generation
- Configurable fee structures
- Bulk student import via Excel

### 📅 **Event Management**
- Event planning and coordination
- Cost tracking and budgeting
- Student registration system
- Attendance management

### 🔒 **Security Features**
- Token-based authentication
- SQL injection prevention
- XSS protection
- CSRF token validation
- Password hashing (bcrypt)
- Rate limiting

## 🛠️ Technology Stack

- **Backend**: PHP 8.0+, MySQL 8.0+
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5.3.0
- **Libraries**: PhpSpreadsheet, PHPMailer
- **Security**: JWT tokens, prepared statements, input sanitization
- **Responsive**: Mobile-first design approach

## 🚀 Quick Start

### Prerequisites
- PHP 8.0 or higher
- MySQL 5.7+ or MariaDB 10.4+
- Web server (Apache/Nginx) or XAMPP
- Composer

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/cesa-fund-management-system.git
   cd cesa-fund-management-system
   ```

2. **Install dependencies**
   ```bash
   composer install
   ```

3. **Setup database**
   ```bash
   # Create database
   mysql -u root -p -e "CREATE DATABASE fund_management;"
   
   # Import schema
   mysql -u root -p fund_management < cs_fund_management.sql
   ```

4. **Configure the application**
   ```bash
   # Copy sample config
   cp config_sample.php config.php
   
   # Edit config.php with your database and email settings
   nano config.php
   ```

5. **Set permissions**
   ```bash
   chmod 755 uploads/
   chmod 644 config.php
   ```

6. **Access the application**
   - Open `http://localhost/cesa-fund-management-system`
   - Login with demo accounts above

## 📱 Screenshots

### Admin Dashboard
![Admin Dashboard](screenshots/admin-dashboard.png)

### Student Portal
![Student Portal](screenshots/student-portal.png)

### Payment Management
![Payment Management](screenshots/payment-management.png)

*Note: Screenshots coming soon!*

## 🏗️ Project Structure

```
cesa-fund-management-system/
├── 📁 admin_dashboard.html      # Administrator interface
├── 📁 teacher_dashboard.html    # Teacher interface  
├── 📁 student_dashboard.html    # Student interface
├── 📁 api.php                   # Central API endpoint
├── 📁 config_sample.php         # Sample configuration (safe for GitHub)
├── 📁 includes/                 # Backend modules
├── 📁 uploads/                  # File storage
├── 📁 vendor/                   # Composer dependencies
├── 📁 cs_fund_management.sql    # Database schema
└── 📁 README.md                 # This file
```

## 🔧 Configuration

### Database Settings
```php
define('DB_HOST', 'localhost');
define('DB_USERNAME', 'your_username');
define('DB_PASSWORD', 'your_password');
define('DB_NAME', 'fund_management');
```

### Email Configuration
```php
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_USERNAME', 'your_email@gmail.com');
define('SMTP_PASSWORD', 'your_app_password');
```

## 🚀 Deployment

### Local Development
- Use XAMPP/WAMP for local development
- Configure `config.php` with local database settings
- Enable error reporting for debugging

### Production Server
- Use the provided `deploy.sh` script for automated deployment
- Follow the `deployment_guide.md` for manual setup
- Ensure SSL certificate and security hardening

## 📊 API Documentation

The system uses a RESTful API approach with a single `api.php` endpoint:

- **Authentication**: `POST /api.php?action=login`
- **User Management**: `POST /api.php?action=get_users`
- **Transactions**: `POST /api.php?action=get_transactions`
- **Events**: `POST /api.php?action=get_events`

## 🧪 Testing

### Manual Testing
1. Test all user roles (Student, Teacher, Admin)
2. Verify payment processing workflows
3. Test file upload functionality
4. Check responsive design on mobile devices

### Automated Testing
- Database connection tests
- API endpoint validation
- Security vulnerability scans

## 🔒 Security Considerations

### Before Going Live
- [ ] Change all default passwords
- [ ] Update JWT secrets and salts
- [ ] Configure proper email settings
- [ ] Enable HTTPS/SSL
- [ ] Set up firewall rules
- [ ] Configure backup systems

### Ongoing Security
- Regular security updates
- Monitor access logs
- Backup verification
- SSL certificate renewal

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Bootstrap Team** for the responsive UI framework
- **PhpSpreadsheet** for Excel file processing
- **PHPMailer** for email functionality
- **CESA Team** for requirements and testing

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/cesa-fund-management-system/issues)
- **Documentation**: Check the `docs/` folder
- **Email**: your-email@example.com

## 🌟 Show Your Support

If you find this project helpful, please give it a ⭐️ star on GitHub!

---

**Built with ❤️ for educational institutions**

**Project Status**: ✅ Production Ready | **Version**: 1.0 | **Last Updated**: January 2025 