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


# Password Storage in Plain Text Vulnerability Fix Documentation

## Vulnerability Details

**OWASP Category**: A02:2021 – Cryptographic Failures  
**CWE ID**: CWE-256: Plaintext Storage of a Password

## 1. Vulnerability Description

The application stores user passwords as plain text in the database. This is a critical security vulnerability as it means that:

1. Anyone with database access (including administrators, backup operators, or attackers who gain unauthorized access) can see all user passwords directly.
2. If the database is compromised, all user accounts are immediately at risk.
3. User privacy is violated, as many users reuse passwords across different services.

## 2. Vulnerability Location

This vulnerability exists in the following locations:

1. **User Model**: `backend/models/User.js` - The schema definition does not hash passwords before storing.
2. **Registration Routes**: `backend/routes/userRoutes.js` - Passwords are stored directly as received from the client.
3. **Login Route**: `backend/routes/userRoutes.js` - Password comparison is done by direct string comparison instead of secure hash verification.
4. **Admin/Seller Creation**: Other routes that create users store passwords in plain text.

## 3. Vulnerability Evidence

### Before Fix:

#### User Model Definition (User.js):
```javascript
const userSchema = new mongoose.Schema({
  id: { type: String, unique: true }, // Custom ID
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // Plain text password
  phone: { type: String },
  userLevel: { type: Number, default: 0 }, // 0: Customer, 1: Seller, 2: Admin
  shopId: { type: String, default: null }, // Only for sellers
});
```

#### User Registration (userRoutes.js):
```javascript
router.post("/register", async (req, res) => {
  const { name, email, password, phone } = req.body;

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    const user = new User({
      name,
      email,
      password, // Store plain text password
      phone,
      userLevel: 0,
    });
    await user.save();

    res.status(201).json({ message: "User registered successfully", user });
  } catch (error) {
    console.error("Failed to register user:", error.message);
    res.status(400).json({ message: "Failed to register user", error: error.message });
  }
});
```

#### User Login (userRoutes.js):
```javascript
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Compare passwords directly (this should be hashed in a real application)
    if (user.password !== password) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    
    // Rest of login code...
  } catch (error) {
    console.error("Failed to login user:", error.message);
    res.status(400).json({ message: "Failed to login user", error: error.message });
  }
});
```

### Database Evidence:

Screenshot showing plain text passwords in the MongoDB database:
![Database with plain text passwords](./evidence/vulnerability5/before_db_plaintext_passwords.png)

## 4. Security Impact

1. **Confidentiality**: HIGH - All user passwords are exposed to anyone with database access.
2. **Integrity**: HIGH - Attackers could gain unauthorized access to any user account.
3. **Availability**: MEDIUM - Compromised accounts could be locked out by attackers.

**Risk Rating**: CRITICAL

The CVSS score for this vulnerability would be approximately 9.8 (Critical) because:
- Attack Vector: Network (user login is accessible remotely)
- Attack Complexity: Low (no special conditions needed)
- Privileges Required: None (affects the authentication system itself)
- User Interaction: None (no user interaction needed for the vulnerability to be exploited)
- Scope: Changed (compromises other accounts beyond the vulnerable component)
- Confidentiality/Integrity/Availability: High impact across all three

## 5. Vulnerability Fix

### Step 1: Install bcrypt package
```bash
cd backend
npm install bcrypt --save
```

### Step 2: Update User Model to hash passwords (User.js)

```javascript
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // Will store hashed password
  phone: { type: String },
  userLevel: { type: Number, default: 0 }, // 0: Customer, 1: Seller, 2: Admin
  shopId: { type: String, default: null }, // Only for sellers
});

// Hash password before saving
userSchema.pre("save", async function (next) {
  // Only hash the password if it's modified (or new)
  if (!this.isModified("password")) return next();
  
  try {
    // Generate a salt with cost factor 10
    const salt = await bcrypt.genSalt(10);
    // Hash the password with the salt
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Add method to compare password for login
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Rest of the model code remains the same
```

### Step 3: Update Login Route (userRoutes.js)

```javascript
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Use the comparePassword method to securely verify password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    
    // Rest of login code remains the same...
  } catch (error) {
    console.error("Failed to login user:", error.message);
    res.status(400).json({ message: "Failed to login user", error: error.message });
  }
});
```

### Step 4: Migrate Existing Users (migration script)

To handle existing users with plain text passwords, we'll need a migration script:

```javascript
// migration-hash-passwords.js
const mongoose = require("mongoose");
const User = require("./models/User");
const bcrypt = require("bcrypt");
require("dotenv").config();

async function migratePasswords() {
  try {
    // Connect to database
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to database for migration");
    
    // Find all users
    const users = await User.find({}).select("+password");
    console.log(`Found ${users.length} users to migrate`);
    
    // Process each user
    for (const user of users) {
      // Check if password might already be hashed (length check is a simple heuristic)
      if (user.password.length < 40) {  // Plain text passwords are typically shorter
        console.log(`Migrating password for user ${user.email}`);
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(user.password, salt);
        await user.save();
      }
    }
    
    console.log("Password migration complete");
    process.exit(0);
  } catch (error) {
    console.error("Migration failed:", error);
    process.exit(1);
  }
}

migratePasswords();
```

## 6. After Fix Evidence

### User Model with Bcrypt Integration:
![Model with bcrypt](./evidence/vulnerability5/after_user_model_with_bcrypt.png)

### Database with Hashed Passwords:
![Database with hashed passwords](./evidence/vulnerability5/after_db_hashed_passwords.png)

### Successful Login Flow:
![Login with bcrypt verification](./evidence/vulnerability5/after_login_flow.png)

## 7. Testing the Fix

### Unit Testing:

```javascript
const bcrypt = require('bcrypt');
const User = require('../models/User');
const mongoose = require('mongoose');

describe('User Password Security Tests', () => {
  let testUser;
  const testPassword = 'SecurePassword123!';
  
  beforeAll(async () => {
    await mongoose.connect(process.env.TEST_MONGO_URI);
  });
  
  afterAll(async () => {
    await User.deleteMany({});
    await mongoose.connection.close();
  });
  
  test('Password should be hashed when user is created', async () => {
    // Create a new user
    testUser = new User({
      name: 'Test User',
      email: 'test@example.com',
      password: testPassword,
      phone: '1234567890',
      userLevel: 0
    });
    
    await testUser.save();
    
    // Verify password is hashed
    expect(testUser.password).not.toBe(testPassword);
    expect(testUser.password.length).toBeGreaterThan(40); // bcrypt hashes are long
  });
  
  test('comparePassword method should correctly verify passwords', async () => {
    // Should match the original password
    const isMatch = await testUser.comparePassword(testPassword);
    expect(isMatch).toBe(true);
    
    // Should reject wrong password
    const isWrongMatch = await testUser.comparePassword('WrongPassword123!');
    expect(isWrongMatch).toBe(false);
  });
  
  test('Changing password should create a new hash', async () => {
    const originalHash = testUser.password;
    testUser.password = 'NewSecurePassword456!';
    await testUser.save();
    
    expect(testUser.password).not.toBe(originalHash);
    expect(testUser.password.length).toBeGreaterThan(40);
  });
});
```

## 8. Security Principles Applied

1. **Defense in Depth**: Added multiple layers of password security (hashing + salting).
2. **Principle of Least Privilege**: Password hashing ensures that even database administrators don't have direct access to user passwords.
3. **Secure by Default**: All passwords are automatically hashed when creating or updating users.
4. **Fail Securely**: Login comparisons use timing-attack safe comparison methods built into bcrypt.

## 9. Technical Implementation Details

### Bcrypt Configuration:

- **Salt Rounds**: 10 (industry standard compromise between security and performance)
- **Hash Algorithm**: Blowfish-based crypt with adaptive rounds
- **Implementation**: Asynchronous methods used to avoid blocking the event loop

### Performance Considerations:

- Bcrypt is intentionally slow to deter brute-force attacks
- The cost factor (10) provides an appropriate balance between security and login response times
- Pre-save middleware ensures consistent hashing across all user creation flows

## 10. Recommendations for Future Improvements

1. Implement password strength requirements during registration
2. Add rate limiting for login attempts
3. Consider adding two-factor authentication
4. Implement automatic password rotation policies for admin accounts
5. Add breach detection for unusual login patterns

## 11. References

1. [OWASP - Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
2. [NIST Special Publication 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
3. [Node.js bcrypt documentation](https://www.npmjs.com/package/bcrypt)
4. [MongoDB Schema Middleware](https://mongoosejs.com/docs/middleware.html)
5. [CWE-256: Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)
# Password Storage in Plain Text Vulnerability Fix Documentation

## Vulnerability Details

**OWASP Category**: A02:2021 – Cryptographic Failures  
**CWE ID**: CWE-256: Plaintext Storage of a Password

## 1. Vulnerability Description

The application stores user passwords as plain text in the database. This is a critical security vulnerability as it means that:

1. Anyone with database access (including administrators, backup operators, or attackers who gain unauthorized access) can see all user passwords directly.
2. If the database is compromised, all user accounts are immediately at risk.
3. User privacy is violated, as many users reuse passwords across different services.

## 2. Vulnerability Location

This vulnerability exists in the following locations:

1. **User Model**: `backend/models/User.js` - The schema definition does not hash passwords before storing.
2. **Registration Routes**: `backend/routes/userRoutes.js` - Passwords are stored directly as received from the client.
3. **Login Route**: `backend/routes/userRoutes.js` - Password comparison is done by direct string comparison instead of secure hash verification.
4. **Admin/Seller Creation**: Other routes that create users store passwords in plain text.

## 3. Vulnerability Evidence

### Before Fix:

#### User Model Definition (User.js):
```javascript
const userSchema = new mongoose.Schema({
  id: { type: String, unique: true }, // Custom ID
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // Plain text password
  phone: { type: String },
  userLevel: { type: Number, default: 0 }, // 0: Customer, 1: Seller, 2: Admin
  shopId: { type: String, default: null }, // Only for sellers
});
```

#### User Registration (userRoutes.js):
```javascript
router.post("/register", async (req, res) => {
  const { name, email, password, phone } = req.body;

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    const user = new User({
      name,
      email,
      password, // Store plain text password
      phone,
      userLevel: 0,
    });
    await user.save();

    res.status(201).json({ message: "User registered successfully", user });
  } catch (error) {
    console.error("Failed to register user:", error.message);
    res.status(400).json({ message: "Failed to register user", error: error.message });
  }
});
```

#### User Login (userRoutes.js):
```javascript
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Compare passwords directly (this should be hashed in a real application)
    if (user.password !== password) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    
    // Rest of login code...
  } catch (error) {
    console.error("Failed to login user:", error.message);
    res.status(400).json({ message: "Failed to login user", error: error.message });
  }
});
```

### Database Evidence:

Screenshot showing plain text passwords in the MongoDB database:
![Database with plain text passwords](./evidence/vulnerability5/before_db_plaintext_passwords.png)

## 4. Security Impact

1. **Confidentiality**: HIGH - All user passwords are exposed to anyone with database access.
2. **Integrity**: HIGH - Attackers could gain unauthorized access to any user account.
3. **Availability**: MEDIUM - Compromised accounts could be locked out by attackers.

**Risk Rating**: CRITICAL

The CVSS score for this vulnerability would be approximately 9.8 (Critical) because:
- Attack Vector: Network (user login is accessible remotely)
- Attack Complexity: Low (no special conditions needed)
- Privileges Required: None (affects the authentication system itself)
- User Interaction: None (no user interaction needed for the vulnerability to be exploited)
- Scope: Changed (compromises other accounts beyond the vulnerable component)
- Confidentiality/Integrity/Availability: High impact across all three

## 5. Vulnerability Fix

### Step 1: Install bcrypt package
```bash
cd backend
npm install bcrypt --save
```

### Step 2: Update User Model to hash passwords (User.js)

```javascript
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // Will store hashed password
  phone: { type: String },
  userLevel: { type: Number, default: 0 }, // 0: Customer, 1: Seller, 2: Admin
  shopId: { type: String, default: null }, // Only for sellers
});

// Hash password before saving
userSchema.pre("save", async function (next) {
  // Only hash the password if it's modified (or new)
  if (!this.isModified("password")) return next();
  
  try {
    // Generate a salt with cost factor 10
    const salt = await bcrypt.genSalt(10);
    // Hash the password with the salt
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Add method to compare password for login
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Rest of the model code remains the same
```

### Step 3: Update Login Route (userRoutes.js)

```javascript
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Use the comparePassword method to securely verify password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    
    // Rest of login code remains the same...
  } catch (error) {
    console.error("Failed to login user:", error.message);
    res.status(400).json({ message: "Failed to login user", error: error.message });
  }
});
```

### Step 4: Migrate Existing Users (migration script)

To handle existing users with plain text passwords, we'll need a migration script:

```javascript
// migration-hash-passwords.js
const mongoose = require("mongoose");
const User = require("./models/User");
const bcrypt = require("bcrypt");
require("dotenv").config();

async function migratePasswords() {
  try {
    // Connect to database
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to database for migration");
    
    // Find all users
    const users = await User.find({}).select("+password");
    console.log(`Found ${users.length} users to migrate`);
    
    // Process each user
    for (const user of users) {
      // Check if password might already be hashed (length check is a simple heuristic)
      if (user.password.length < 40) {  // Plain text passwords are typically shorter
        console.log(`Migrating password for user ${user.email}`);
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(user.password, salt);
        await user.save();
      }
    }
    
    console.log("Password migration complete");
    process.exit(0);
  } catch (error) {
    console.error("Migration failed:", error);
    process.exit(1);
  }
}

migratePasswords();
```

## 6. After Fix Evidence

### User Model with Bcrypt Integration:
![Model with bcrypt](./evidence/vulnerability5/after_user_model_with_bcrypt.png)

### Database with Hashed Passwords:
![Database with hashed passwords](./evidence/vulnerability5/after_db_hashed_passwords.png)

### Successful Login Flow:
![Login with bcrypt verification](./evidence/vulnerability5/after_login_flow.png)

## 7. Testing the Fix

### Unit Testing:

```javascript
const bcrypt = require('bcrypt');
const User = require('../models/User');
const mongoose = require('mongoose');

describe('User Password Security Tests', () => {
  let testUser;
  const testPassword = 'SecurePassword123!';
  
  beforeAll(async () => {
    await mongoose.connect(process.env.TEST_MONGO_URI);
  });
  
  afterAll(async () => {
    await User.deleteMany({});
    await mongoose.connection.close();
  });
  
  test('Password should be hashed when user is created', async () => {
    // Create a new user
    testUser = new User({
      name: 'Test User',
      email: 'test@example.com',
      password: testPassword,
      phone: '1234567890',
      userLevel: 0
    });
    
    await testUser.save();
    
    // Verify password is hashed
    expect(testUser.password).not.toBe(testPassword);
    expect(testUser.password.length).toBeGreaterThan(40); // bcrypt hashes are long
  });
  
  test('comparePassword method should correctly verify passwords', async () => {
    // Should match the original password
    const isMatch = await testUser.comparePassword(testPassword);
    expect(isMatch).toBe(true);
    
    // Should reject wrong password
    const isWrongMatch = await testUser.comparePassword('WrongPassword123!');
    expect(isWrongMatch).toBe(false);
  });
  
  test('Changing password should create a new hash', async () => {
    const originalHash = testUser.password;
    testUser.password = 'NewSecurePassword456!';
    await testUser.save();
    
    expect(testUser.password).not.toBe(originalHash);
    expect(testUser.password.length).toBeGreaterThan(40);
  });
});
```

## 8. Security Principles Applied

1. **Defense in Depth**: Added multiple layers of password security (hashing + salting).
2. **Principle of Least Privilege**: Password hashing ensures that even database administrators don't have direct access to user passwords.
3. **Secure by Default**: All passwords are automatically hashed when creating or updating users.
4. **Fail Securely**: Login comparisons use timing-attack safe comparison methods built into bcrypt.

## 9. Technical Implementation Details

### Bcrypt Configuration:

- **Salt Rounds**: 10 (industry standard compromise between security and performance)
- **Hash Algorithm**: Blowfish-based crypt with adaptive rounds
- **Implementation**: Asynchronous methods used to avoid blocking the event loop

### Performance Considerations:

- Bcrypt is intentionally slow to deter brute-force attacks
- The cost factor (10) provides an appropriate balance between security and login response times
- Pre-save middleware ensures consistent hashing across all user creation flows

## 10. Recommendations for Future Improvements

1. Implement password strength requirements during registration
2. Add rate limiting for login attempts
3. Consider adding two-factor authentication
4. Implement automatic password rotation policies for admin accounts
5. Add breach detection for unusual login patterns

## 11. References

1. [OWASP - Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
2. [NIST Special Publication 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
3. [Node.js bcrypt documentation](https://www.npmjs.com/package/bcrypt)
4. [MongoDB Schema Middleware](https://mongoosejs.com/docs/middleware.html)
5. [CWE-256: Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)
