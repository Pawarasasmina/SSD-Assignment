const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

// Ensure the upload directory exists
const uploadDir = path.join(__dirname, "../uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Define allowed file types
const allowedFileTypes = ['image/jpeg', 'image/png', 'image/gif'];

// Create file filter
const fileFilter = (req, file, cb) => {
  if (allowedFileTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG and GIF are allowed.'), false);
  }
};

// Set up multer for file uploads with enhanced security
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    // Create a safe filename with randomization to prevent path traversal attacks
    const uniqueSuffix = Date.now() + '-' + crypto.randomBytes(6).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase();
    
    // Validate extension
    const validExtensions = ['.jpg', '.jpeg', '.png', '.gif'];
    if (!validExtensions.includes(ext)) {
      return cb(new Error('Invalid file extension'), false);
    }
    
    cb(null, `file-${uniqueSuffix}${ext}`);
  },
});


// Configure multer with limits and file filter
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB size limit
  },
  fileFilter: fileFilter
});

module.exports = upload;