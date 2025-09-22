# PixelPlaza: Secure E-commerce Platform

## Project Information
This repository contains a secure MERN stack e-commerce application (PixelPlaza) that has been hardened against the OWASP Top 10 vulnerabilities. The project demonstrates the implementation of security best practices in a full-stack web application.

## Group Members
- Student Name (IT12345678)
- Student Name (IT12345678)
- Student Name (IT12345678)
- Student Name (IT12345678)

## Links
- [Original Vulnerable Project](https://github.com/username/vulnerable-pixelplaza)
- [Secure Version](https://github.com/username/SE-S1-WD-09-PixelPlaza)
- [YouTube Demo Video](https://youtube.com/watch?v=demo)

## Setup Instructions

### Prerequisites
- Node.js (v16+)
- MongoDB
- Git

### Installation

1. Clone the repository:
```bash
git clone https://github.com/username/SE-S1-WD-09-PixelPlaza.git
cd SE-S1-WD-09-PixelPlaza
```

2. Backend setup:
```bash
cd backend
npm install
# Create a .env file with appropriate configuration
npm start
```

3. Frontend setup:
```bash
cd ../frontend/ui
npm install
npm run dev
```

## Identified Vulnerabilities & Fixes

### 1. A01:2021 – Broken Access Control
**Issue**: Insufficient authorization checks in route handlers allowing users to access/modify resources they shouldn't.

**Fix**: Implemented JWT-based middleware that verifies user roles and permissions before allowing access to protected routes.

### 2. A02:2021 – Cryptographic Failures
**Issue**: User passwords stored in plain text or with weak hashing algorithms.

**Fix**: Implemented bcrypt for password hashing with appropriate salt rounds and secured all sensitive data in transit with HTTPS.

### 3. A03:2021 – Injection
**Issue**: NoSQL injection vulnerabilities in MongoDB queries with unvalidated user input.

**Fix**: Added input validation and sanitization using express-validator and implemented MongoDB query parameterization.

### 4. A05:2021 – Security Misconfiguration
**Issue**: Default configurations and unnecessary exposed services creating security gaps.

**Fix**: Applied Helmet.js to set secure HTTP headers and implemented proper configuration for all environments.

### 5. A07:2021 – Identification and Authentication Failures
**Issue**: Weak password policies and insufficient authentication mechanisms.

**Fix**: Implemented strong password requirements, account lockout mechanisms, and multi-factor authentication options.

### 6. A08:2021 – Software and Data Integrity Failures
**Issue**: Insecure handling of uploads allowing malicious files to be processed.

**Fix**: Implemented robust file validation, content-type checking, and virus scanning for all uploaded files.

### 7. A09:2021 – Security Logging and Monitoring Failures
**Issue**: Insufficient logging of security events making intrusion detection difficult.

**Fix**: Implemented Winston for comprehensive logging of authentication events, access control violations, and other security-relevant activities.

## OAuth/OpenID Connect Implementation

We implemented Google OAuth 2.0 Authorization Code flow to provide secure third-party authentication. This implementation:

- Allows users to sign in with their Google accounts
- Verifies identity using OpenID Connect
- Securely handles access tokens and refresh tokens
- Provides proper session management for authenticated users

## Security Tools Used

1. **npm audit**: For dependency vulnerability scanning
2. **ESLint with security plugins**: For static code analysis to detect security issues
3. **Semgrep**: For pattern-based security scanning
4. **OWASP ZAP**: For dynamic application security testing
5. **MongoDB Compass**: For database security assessment

## Evidence

### Vulnerability Scanning Results
- `/evidence/npm-audit-results.pdf`
- `/evidence/semgrep-scan-results.pdf`
- `/evidence/zap-scan-report.pdf`

### Vulnerability Demonstrations
- `/evidence/screenshots/before-fix-injection.png`
- `/evidence/screenshots/after-fix-injection.png`
- `/evidence/curl/authentication-bypass-demo.txt`

### OAuth Implementation
- `/evidence/screenshots/oauth-flow-demonstration.png`
- `/evidence/oauth-sequence-diagram.pdf`

## Individual Contributions

| Student ID | Contributions |
|------------|---------------|
| IT12345678 | A01: Broken Access Control, A05: Security Misconfiguration |
| IT12345678 | A02: Cryptographic Failures, OAuth Implementation |
| IT12345678 | A03: Injection, A09: Security Logging and Monitoring Failures |
| IT12345678 | A07: Identification and Authentication Failures, A08: Software and Data Integrity Failures |

---

*This project was developed as part of the SE4030 Secure Software Development module at SLIIT.*