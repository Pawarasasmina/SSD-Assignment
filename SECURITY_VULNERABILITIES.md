# Security Vulnerabilities in Healthcare Management System

This document identifies 7 security vulnerabilities in the current implementation of the Healthcare Management System, aligned with the OWASP Top 10 2021 categories, and provides detailed instructions on how to fix them.

## Vulnerability 1: Hardcoded Database Credentials (A07:2021 – Identification and Authentication Failures)

### Issue
Database credentials are hardcoded in `db.js`, exposing sensitive connection information in the source code.

### Fix
Move credentials to environment variables:

1. Update `.env` file (create if doesn't exist):
```
MONGO_URI=mongodb+srv://username:password@cluster0.y694y.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0
```

2. Modify `db.js` to use environment variables:
```javascript
const mongoose = require("mongoose");
require("dotenv").config();

const dburl = process.env.MONGO_URI;

if (!dburl) {
  console.error("MONGO_URI is not defined in environment variables");
  process.exit(1);
}

mongoose.set("strictQuery", true, "userNewUrlParser", true);

const connection = async () => {
  try {
    await mongoose.connect(dburl);
    console.log("MongoDB Connected~");
  } catch (e) {
    console.error(e.message);
    process.exit();
  }
};

module.exports = connection;
```

## Vulnerability 2: Hardcoded JWT Secrets (A05:2021 – Security Misconfiguration)

### Issue
The application uses a hardcoded JWT secret in the `userRoutes.js` file, which is a security risk. The secret should not be exposed in the source code.

### Fix
1. Add JWT secret to environment variables in `.env` file:
```
JWT_SECRET=your_secure_random_secret
```

2. Update `userRoutes.js` to use the environment variable:
```javascript
// Load environment variables
require('dotenv').config();

// JWT Secret Key from environment variable
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('JWT_SECRET is not defined in environment variables');
  process.exit(1);
}

// Rest of the code...
```

3. Use the `generateSecret.js` script to create a secure random secret, and store this in the `.env` file.

## Vulnerability 3: Missing Security Headers & CORS Misconfiguration (A05:2021 – Security Misconfiguration)

### Issue
The application lacks important security headers and has a permissive CORS policy which can expose it to various attacks such as XSS, clickjacking, etc.

### Fix
Install and implement Helmet.js to add security headers and restrict CORS:

1. Install Helmet:
```bash
npm install helmet --save
```

2. Update `server.js`:
```javascript
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const helmet = require('helmet');
require("dotenv").config(); // Load environment variables

const app = express();
const port = process.env.PORT || 3000;

// Apply Helmet middleware to set security headers
app.use(helmet());

// Configure CORS with more restrictive settings
app.use(
  cors({
    origin: process.env.NODE_ENV === 'production' 
      ? 'https://your-production-domain.com' 
      : 'http://localhost:5173',
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400, // Cache preflight requests for 1 day
  })
);

// Rest of the code...
```

## Vulnerability 4: Lack of Input Validation (A04:2021 – Insecure Design)

### Issue
Many routes don't properly validate or sanitize user input, making the application vulnerable to injection attacks, XSS, and other types of attacks.

### Fix
Implement comprehensive input validation and sanitization across all routes:

1. Install additional packages:
```bash
npm install express-validator xss-clean --save
```

2. Create a validation middleware file `middleware/validation.js`:
```javascript
const { body, param, validationResult } = require('express-validator');
const xss = require('xss-clean');

// Common validation middleware
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// XSS prevention middleware
const preventXSS = xss();

// User registration validation
const validateUserRegistration = [
  body('name').trim().notEmpty().withMessage('Name is required')
    .isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters'),
  body('email').trim().isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])/).withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  body('phone').optional().isMobilePhone().withMessage('Please provide a valid phone number'),
  validateRequest
];

// Product validation
const validateProduct = [
  body('name').trim().notEmpty().withMessage('Product name is required'),
  body('price').isNumeric().withMessage('Price must be a number'),
  body('description').trim().notEmpty().withMessage('Description is required'),
  body('category').trim().notEmpty().withMessage('Category is required'),
  validateRequest
];

module.exports = {
  validateUserRegistration,
  validateProduct,
  preventXSS
};
```

3. Apply these validations in your routes:
```javascript
const express = require("express");
const router = express.Router();
const { validateUserRegistration, preventXSS } = require('../middleware/validation');
const User = require("../models/User");

// Apply XSS prevention to all routes
router.use(preventXSS);

// Register user with validation
router.post("/register", validateUserRegistration, async (req, res) => {
  // Rest of the code...
});

// Rest of the code...
```

## Vulnerability 5: Password Storage in Plain Text (A02:2021 – Cryptographic Failures)

### Issue
The application stores user passwords in plain text in the database, as seen in the `User.js` model and the registration routes. This is a serious security risk as it exposes user credentials if the database is compromised.

### Fix
Implement password hashing using bcrypt:

1. Install bcrypt:
```bash
npm install bcrypt --save
```

2. Modify the User.js model to hash passwords before saving:
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
  if (!this.isModified("password")) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Add method to compare password
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Rest of the code...
```

3. Update login route to use the comparePassword method:
```javascript
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Use the comparePassword method
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Rest of the login process...
  } catch (error) {
    console.error("Failed to login user:", error.message);
    res
      .status(400)
      .json({ message: "Failed to login user", error: error.message });
  }
});
```

## Vulnerability 6: NoSQL Injection (A03:2021 – Injection)

### Issue
The application uses MongoDB queries with unvalidated user input, particularly in routes like `cartproductRoutes.js`, which makes it susceptible to NoSQL injection attacks.

### Fix
Implement data validation and sanitization:

1. Install validator package:
```bash
npm install express-validator --save
```

2. Implement validation in routes:
```javascript
const express = require("express");
const router = express.Router();
const { body, param, validationResult } = require('express-validator');
const cartProduct = require("../models/cartProduct");

router.get("/test", (req, res) => res.send("route is working"));

// Validation middleware
const validateCartProduct = [
  body('productId').notEmpty().isString(),
  body('userId').notEmpty().isString(),
  body('quantity').isInt({ min: 1 }),
  body('price').isNumeric()
];

// Add cart product with validation
router.post("/", validateCartProduct, (req, res) => {
  // Check for validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  cartProduct
    .create(req.body)
    .then(() => res.json({ msg: "Successfully added to the cart" }))
    .catch((error) => res.status(400).json({ msg: "Cart adding failed", error: error.message }))
});

// Get cart items by ID with validation
router.get("/:id", param('id').isMongoId(), (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  cartProduct
    .findById(req.params.id)
    .then((cartProduct) => {
      if (!cartProduct) {
        return res.status(404).json({ msg: "Cart item not found" });
      }
      res.json(cartProduct);
    })
    .catch((error) => res.status(400).json({ msg: "CartItems getting by id failed", error: error.message }))
});

// Rest of the code...
```

## Vulnerability 7: Insecure File Upload Configuration (A01:2021 – Broken Access Control)

### Issue
The file upload configuration in `multerConfig.js` doesn't validate file types or restrict file sizes, which could lead to malicious file uploads.

### Fix
Enhance the multer configuration:

```javascript
const multer = require("multer");
const path = require("path");
const fs = require("fs");

// Ensure the upload directory exists
const uploadDir = path.join(__dirname, "../uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Define allowed file types
const allowedFileTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];

// Set up multer for file uploads with enhanced security
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir); // Use the upload directory path
  },
  filename: function (req, file, cb) {
    // Create a safe filename to prevent path traversal attacks
    const sanitizedFilename = file.originalname.replace(/[^a-zA-Z0-9\-_.]/g, '_');
    cb(null, Date.now() + '-' + sanitizedFilename); // Create a unique filename
  },
});

// Create file filter
const fileFilter = (req, file, cb) => {
  if (allowedFileTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only jpeg, png, gif and pdf are allowed.'), false);
  }
};

// Configure multer with limits and file filter
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB size limit
  },
  fileFilter: fileFilter
});

module.exports = upload;
```

## OWASP Top 10 2021 Coverage

The vulnerabilities identified and fixed in this document cover the following categories from the OWASP Top 10 2021:

1. **A01:2021 – Broken Access Control** - Addressed in Vulnerability 7 with secure file upload configuration
2. **A02:2021 – Cryptographic Failures** - Addressed in Vulnerability 5 with proper password hashing
3. **A03:2021 – Injection** - Addressed in Vulnerability 6 with input validation for NoSQL queries
4. **A04:2021 – Insecure Design** - Addressed in Vulnerability 4 with comprehensive input validation
5. **A05:2021 – Security Misconfiguration** - Addressed in Vulnerabilities 2 and 3 with proper JWT secret management and security headers
6. **A07:2021 – Identification and Authentication Failures** - Addressed in Vulnerability 1 with secure credential management

## Best Practices to Prevent These Vulnerabilities

1. **Regular Security Audits**: Conduct periodic security audits of the codebase to identify and address potential vulnerabilities.
2. **Developer Training**: Ensure developers are trained on secure coding practices and common web application vulnerabilities.
3. **Implement SAST/DAST Tools**: Use Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST) tools in the development pipeline.
4. **Follow Security-by-Design Principles**: Incorporate security considerations from the beginning of the software development lifecycle.
5. **Use Security Libraries and Frameworks**: Leverage established security libraries rather than implementing security features from scratch.
6. **Keep Dependencies Updated**: Regularly update dependencies to patch known vulnerabilities.
7. **Principle of Least Privilege**: Implement access controls based on the principle of least privilege.
8. **Input Validation and Output Encoding**: Always validate input and encode output to prevent injection attacks.
