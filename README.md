# SE4030 – Secure Software Development Assignment

## Group Information
- Member 1: [Your Name] - [Your ID]
- Member 2: [Team Member Name] - [ID]
- Member 3: [Team Member Name] - [ID]
- Member 4: [Team Member Name] - [ID]

## Project Links
- **Original Project**: [Link to the original Healthcare Management System]
- **Modified Project**: [Link to your fixed repository]
- **Video Presentation**: [YouTube Link - To be added]

## Project Overview
This repository contains a Healthcare Management System with implemented security fixes. The application includes both frontend (React) and backend (Node.js/Express) components. The original application contained several security vulnerabilities that have been identified and fixed as part of this assignment.

## Security Vulnerabilities and Fixes

We have identified and fixed the following 7 security vulnerabilities in the application, aligned with OWASP Top 10 2021 categories:



### 1. Hardcoded Database Credentials (A07:2021 – Identification and Authentication Failures)
**Issue**: Hardcoded database credentials in source code.

**Fix**: Moved database connection strings to environment variables and implemented proper secret management.

### 2. Hardcoded JWT Secrets (A05:2021 – Security Misconfiguration)
**Issue**: Hardcoded JWT secrets in source code.

**Fix**: Moved all sensitive JWT configuration to environment variables using dotenv.

### 3. Missing Security Headers & CORS Misconfiguration (A05:2021 – Security Misconfiguration)
**Issue**: Missing security headers and permissive CORS policy.

**Fix**: Implemented Helmet.js for security headers and restricted CORS configuration.

### 4. Lack of Input Validation (A04:2021 – Insecure Design)
**Issue**: Lack of input validation and sanitization across multiple routes.

**Fix**: Implemented comprehensive validation and sanitization middleware for all user inputs.

### 5. Password Storage in Plain Text (A02:2021 – Cryptographic Failures)
**Issue**: Passwords stored in plain text in the database.

**Fix**: Implemented bcrypt password hashing for secure password storage and verification.

### 6. NoSQL Injection (A03:2021 – Injection)
**Issue**: NoSQL injection vulnerabilities in MongoDB queries with unvalidated user input.

**Fix**: Implemented express-validator for input validation and parameterized MongoDB queries.

### 7. Insecure File Upload Configuration (A01:2021 – Broken Access Control)
**Issue**: Insecure file upload configuration allowing potentially malicious files.

**Fix**: Implemented proper file type validation, size restrictions, and secure file naming.

## OAuth Implementation

We have successfully implemented Google OAuth authentication in the application. This implementation:

1. Allows users to sign in using their Google accounts
2. Securely handles authentication tokens
3. Stores relevant user information in the database
4. Follows OAuth 2.0 best practices for web applications

## Testing Tools Used
- OWASP ZAP for dynamic application security testing
- npm audit for dependency vulnerability scanning
- MongoDB Compass for database integrity verification
- Postman for API endpoint testing
- Browser developer tools for frontend security analysis

## Running the Application

### Prerequisites
- Node.js (v14 or higher)
- MongoDB instance
- npm or yarn package manager

### Backend Setup
1. Navigate to the backend directory:
```
cd backend
```

2. Install dependencies:
```
npm install
```

3. Create a `.env` file with the following variables:
```
PORT=3000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

4. Start the server:
```
npm start
```

### Frontend Setup
1. Navigate to the frontend directory:
```
cd frontend
```

2. Install dependencies:
```
npm install
```

3. Start the development server:
```
npm run dev
```

4. Access the application at http://localhost:5173

## Best Practices Implemented
- Secure password storage using bcrypt
- Environment variable management for secrets
- Input validation and sanitization
- CORS protection
- Security headers using Helmet.js
- XSS prevention
- File upload security measures
- MongoDB query injection prevention
- OAuth 2.0 implementation best practices

## Detailed Documentation
For more detailed information about each vulnerability and the implemented fixes, please refer to the [SECURITY_VULNERABILITIES.md](./SECURITY_VULNERABILITIES.md) file in this repository.

## Screenshots
- [Before Fix: Plain Text Password Storage](/evidence/screenshots/before-fix-password.png)
- [After Fix: Hashed Password Implementation](/evidence/screenshots/after-fix-password.png)
- [Before Fix: NoSQL Injection](/evidence/screenshots/before-fix-injection.png)
- [After Fix: Parameterized Queries](/evidence/screenshots/after-fix-injection.png)

## Individual Contributions

| Member ID | Vulnerabilities Fixed |
|----------|------------------------|
| IT22137500 | Hardcoded Database Credentials (A07: Identification and Authentication Failures), Hardcoded JWT Secrets (A05: Security Misconfiguration) |
| IT23456789 | Missing Security Headers & CORS Misconfiguration (A05: Security Misconfiguration), Lack of Input Validation (A04: Insecure Design) |
| IT22166906 | Password Storage in Plain Text (A02: Cryptographic Failures) + OAuth Implementation |
| IT22289520 | NoSQL Injection (A03: Injection), Insecure File Upload Configuration (A01: Broken Access Control) |

## References
1. [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
2. [Express.js Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
3. [MongoDB Security](https://docs.mongodb.com/manual/security/)
4. [React Security Best Practices](https://reactjs.org/docs/security.html)
5. [OAuth 2.0 for Web Applications](https://oauth.net/2/)


## Vulnerabilities Not Fixed

While we've addressed the seven major vulnerabilities in our application, there are some security concerns that remain unaddressed due to various constraints:

### 1. Outdated Dependencies (A06:2021 - Vulnerable and Outdated Components)

**Issue**: The application uses several outdated npm packages with known security vulnerabilities.

**Reason for not fixing**: 
- Complete dependency updates would require extensive regression testing
- Some legacy features depend on specific versions of these packages
- Certain package updates would require significant code refactoring beyond the scope of this assignment

**Mitigation**: A comprehensive dependency update plan has been documented for future implementation phases.

### 2. Rate Limiting (A04:2021 - Insecure Design)

**Issue**: The API lacks rate limiting, making it vulnerable to brute force attacks and potential DoS situations.

**Reason for not fixing**:
- Implementation requires changes to the infrastructure configuration
- Current hosting environment has limitations for implementing proper rate limiting
- Would require modifications to authentication flow and user experience

**Mitigation**: Documentation added to highlight this as a priority for the next security enhancement phase.

### 3. Server-Side Request Forgery (SSRF) Protection (A10:2021 - Server-Side Request Forgery)

**Issue**: The application makes HTTP requests based on user input in some admin features without proper validation.

**Reason for not fixing**:
- This vulnerability exists in rarely-used administrative features
- Complete fix requires architectural changes to how external services are called
- Limited potential impact due to internal network configuration

**Mitigation**: Admin documentation updated to warn about the potential security implications.

### 4. Security Logging and Monitoring (A09:2021 - Security Logging and Monitoring Failures)

**Issue**: The application has insufficient logging of security events and lacks a proper monitoring system.

**Reason for not fixing**:
- Requires implementation of a comprehensive logging infrastructure
- Needs integration with external monitoring tools
- Storage and processing of logs requires additional infrastructure planning

**Mitigation**: Basic error logging has been enhanced, but comprehensive security logging remains a future task.