const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const multer = require("multer");
const helmet = require('helmet'); // Add helmet import
require("dotenv").config(); // Load environment variables

const app = express();
const port = 3000;

// Apply Helmet middleware to set security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://apis.google.com", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://lh3.googleusercontent.com"],
      connectSrc: ["'self'", "https://www.googleapis.com"]
    }
  },
  crossOriginEmbedderPolicy: false // Disable for OAuth compatibility
}));

// Configure CORS with more restrictive settings
app.use(
  cors({
    origin: process.env.NODE_ENV === 'production' 
      ? process.env.ALLOWED_ORIGINS?.split(',') || 'https://your-production-domain.com'
      : 'http://localhost:5173',
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400, // Cache preflight requests for 1 day
  })
);

// Add custom security headers
app.use((req, res, next) => {
  // Additional security headers
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (uploads) with proper CORS headers
app.use('/uploads', (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', process.env.NODE_ENV === 'production' 
    ? process.env.ALLOWED_ORIGINS?.split(',')[0] || 'https://your-production-domain.com'
    : 'http://localhost:5173');
  res.setHeader('Access-Control-Allow-Methods', 'GET');
  res.setHeader('Cache-Control', 'public, max-age=31536000'); // Cache for 1 year
  next();
}, express.static('uploads'));

// MongoDB Connection
const mongoURI =
  process.env.MONGO_URI ||
  "";
mongoose
  .connect(mongoURI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Routes
const productRoutes = require("./routes/productRoutes");
app.use("/api/products", productRoutes);

const promotionRoutes = require("./routes/promotionRoutes");
app.use("/api/promotions", promotionRoutes);

const userRoutes = require("./routes/userRoutes"); // Import userRoutes
app.use("/api/users", userRoutes); // Use the userRoutes for the /api/users endpoint

const salesRoutes = require("./routes/shops");
app.use("/api/shops", salesRoutes);

const cartproductRoutes = require("./routes/cartproductRoutes");
app.use("/api/cartProduct", cartproductRoutes);

const previousOrderRoutes = require("./routes/previousOrderRoutes");
app.use("/api/previousOrders", previousOrderRoutes);

const wishlistRoutes = require("./routes/wishlistRoutes");
app.use("/api/wishlist", wishlistRoutes);

const feedback = require("./routes/feedback");
app.use("/api/feedback", feedback);

// Multer error handling middleware
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File too large. Maximum size is 5MB.' });
    }
    return res.status(400).json({ message: 'File upload error', error: err.message });
  }
  next(err);
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
