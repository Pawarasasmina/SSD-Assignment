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