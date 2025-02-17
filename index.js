const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const fs = require('fs');
const path = require('path');
const { body, validationResult } = require("express-validator");
require("dotenv").config();

const app = express();
app.use(express.json());

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`, {
    headers: req.headers,
    body: req.body,
    query: req.query
  });
  next();
});

const uploadDir = path.join(__dirname, 'uploads');
console.log('Upload directory path:', uploadDir);
try {
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
  }
  fs.accessSync(uploadDir, fs.constants.W_OK);
  console.log('Upload directory verified with write permissions');
} catch (error) {
  console.error('Error setting up upload directory:', error);
  process.exit(1);
}

try {
  const requiredEnvVars = ['CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET'];
  requiredEnvVars.forEach(varName => {
    if (!process.env[varName]) {
      throw new Error(`Missing required environment variable: ${varName}`);
    }
  });

  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });
} catch (error) {
  console.error('Cloudinary configuration error:', error);
  process.exit(1);
}

const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function(req, file, cb) {
    const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
    const uniqueSuffix = Date.now() + '_' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '_' + sanitizedName);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ["image/jpeg", "image/png", "image/jpg", "application/pdf"];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`Invalid file type. Allowed types: ${allowedTypes.join(', ')}`), false);
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: fileFilter
});

// Updated Schema Definitions
const prescriptionSchema = new mongoose.Schema({
  uploadId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Upload',
    required: true 
  },
  url: { 
    type: String, 
    required: true 
  },
  uploadDate: { 
    type: Date, 
    default: Date.now 
  },
  type: { 
    type: String, 
    enum: ['file', 'link'],
    required: true 
  }
});

const userSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: true,
    trim: true,
    minlength: [2, 'Name must be at least 2 characters long']
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email']
  },
  password: { 
    type: String, 
    required: true,
    minlength: [6, 'Password must be at least 6 characters long']
  },
  prescriptions: [prescriptionSchema],
}, {
  timestamps: true
});

const User = mongoose.model("User", userSchema);

const uploadSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: "User", 
    required: true,
    index: true
  },
  type: { 
    type: String, 
    enum: ["file", "link"], 
    required: true 
  },
  url: { 
    type: String, 
    required: true,
    validate: {
      validator: function(v) {
        return /^https?:\/\/.+/.test(v);
      },
      message: 'URL must be a valid HTTP/HTTPS URL'
    }
  },
  originalName: String,
  mimeType: String,
  size: Number,
  uploadDate: { 
    type: Date, 
    default: Date.now 
  },
  status: { 
    type: String, 
    enum: ["pending", "completed", "failed"], 
    default: "pending" 
  }
}, {
  timestamps: true
});

const Upload = mongoose.model("Upload", uploadSchema);

// Authentication Middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
      return res.status(401).json({ message: "Authorization header missing" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Bearer token missing" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    req.user = decoded;
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ message: "Token expired" });
    }
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({ message: "Invalid token" });
    }
    return res.status(500).json({ message: "Authentication error", error: error.message });
  }
};





//routes

// Routes and Server Setup

// User Signup with enhanced validation
app.post("/api/signup", [
  body('name').trim().isLength({ min: 2 }).escape(),
  body('email').trim().isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(201).json({
      message: "User created successfully",
      token,
      user: { id: user._id, name, email }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: "Error creating user", error: error.message });
  }
});

// User Login with enhanced security
app.post("/api/login", [
  body('email').trim().isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: { id: user._id, name: user.name, email: user.email }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: "Error logging in", error: error.message });
  }
});

// Updated File Upload Endpoint
app.post("/api/upload/file", authenticateToken, upload.single("file"), async (req, res) => {
  let uploadedFile = null;
  try {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }
    uploadedFile = req.file;

    console.log("File saved at:", req.file.path);
    
    const result = await cloudinary.uploader.upload(req.file.path, {
      resource_type: "auto",
      folder: "prescriptions",
      timeout: 60000
    }).catch(error => {
      console.error("Cloudinary upload failed:", error);
      throw new Error("Failed to upload to cloud storage");
    });

    const uploadDoc = new Upload({
      userId: req.user.userId,
      type: "file",
      url: result.secure_url,
      originalName: req.file.originalname,
      mimeType: req.file.mimetype,
      size: req.file.size,
      status: "completed"
    });

    await uploadDoc.save();

    // Ensure the uploadId is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(uploadDoc._id)) {
      throw new Error('Invalid Upload ID');
    }

    const prescriptionData = {
      uploadId: uploadDoc._id,
      url: result.secure_url,
      uploadDate: new Date(),
      type: 'file'
    };
    
    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      { 
        $push: { 
          prescriptions: prescriptionData
        } 
      },
      { 
        new: true, 
        runValidators: true 
      }
    );

    if (!updatedUser) {
      throw new Error('User not found while updating prescriptions');
    }

    // Clean up local file
    fs.unlink(req.file.path, (err) => {
      if (err) console.error('Error removing temporary file:', err);
    });

    res.json({ 
      message: "File uploaded successfully",
      upload: {
        id: uploadDoc._id,
        url: result.secure_url,
        originalName: req.file.originalname,
        type: 'file'
      }
    });
  } catch (error) {
    console.error('File upload error:', error);
    
    if (uploadedFile && uploadedFile.path) {
      fs.unlink(uploadedFile.path, (err) => {
        if (err) console.error('Error removing temporary file:', err);
      });
    }

    if (error instanceof multer.MulterError) {
      return res.status(400).json({ message: "File upload error", error: error.message });
    }

    res.status(500).json({ 
      message: "Error uploading file", 
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Upload Link Endpoint
app.post("/api/upload/link", authenticateToken, [
  body('url')
    .isURL().withMessage('Please provide a valid URL')
    .matches(/\.(jpg|jpeg|png|pdf)$/i).withMessage('URL must point to a JPG, PNG or PDF file')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { url } = req.body;

    const uploadDoc = new Upload({
      userId: req.user.userId,
      type: "link",
      url: url,
      status: "completed"
    });

    await uploadDoc.save();

    // Ensure the uploadId is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(uploadDoc._id)) {
      throw new Error('Invalid Upload ID');
    }

    const prescriptionData = {
      uploadId: uploadDoc._id,
      url: url,
      uploadDate: new Date(),
      type: 'link'
    };

    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      { 
        $push: { 
          prescriptions: prescriptionData
        } 
      },
      { 
        new: true, 
        runValidators: true 
      }
    );

    if (!updatedUser) {
      throw new Error('User not found while updating prescriptions');
    }

    res.json({
      message: "Link uploaded successfully",
      upload: {
        id: uploadDoc._id,
        url: url,
        type: 'link'
      }
    });
  } catch (error) {
    console.error('Link upload error:', error);
    
    // If there was an error and the upload document was created, try to delete it
    if (error.uploadDoc && error.uploadDoc._id) {
      try {
        await Upload.findByIdAndDelete(error.uploadDoc._id);
      } catch (deleteError) {
        console.error('Error cleaning up upload document:', deleteError);
      }
    }

    res.status(500).json({ 
      message: "Error processing link upload", 
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined 
    });
  }
});

// Get Uploads Endpoint
app.get("/api/uploads", authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;

    const uploads = await Upload.find({ userId: req.user.userId })
      .sort({ uploadDate: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Upload.countDocuments({ userId: req.user.userId });

    res.json({ 
      uploads,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      totalUploads: total
    });
  } catch (error) {
    console.error('Fetch uploads error:', error);
    res.status(500).json({ message: "Error fetching uploads", error: error.message });
  }
});

// Delete Upload Endpoint
app.delete("/api/uploads/:uploadId", authenticateToken, async (req, res) => {
  try {
    const upload = await Upload.findOne({
      _id: req.params.uploadId,
      userId: req.user.userId
    });

    if (!upload) {
      return res.status(404).json({ message: "Upload not found" });
    }

    if (upload.type === "file") {
      try {
        const publicId = `prescriptions/${path.basename(upload.url.split('/').pop(), path.extname(upload.url))}`;
        await cloudinary.uploader.destroy(publicId);
      } catch (cloudinaryError) {
        console.error('Error deleting from Cloudinary:', cloudinaryError);
      }
    }

    await User.findByIdAndUpdate(req.user.userId, {
      $pull: {
        prescriptions: { uploadId: upload._id }
      }
    });

    await upload.deleteOne();
    res.json({ message: "Upload deleted successfully" });
  } catch (error) {
    console.error('Delete upload error:', error);
    res.status(500).json({ message: "Error deleting upload", error: error.message });
  }
});

// Continuing from Global Error Handler
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  
  if (req.file) {
    fs.unlink(req.file.path, (err) => {
      if (err) console.error('Error removing temporary file:', err);
    });
  }

  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        message: "File too large",
        error: "Maximum file size is 10MB"
      });
    }
    return res.status(400).json({
      message: "File upload error",
      error: error.message
    });
  }

  res.status(500).json({
    message: "Internal server error",
    error: error.message,
    stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
  });
});

// Database Connection with Retry Logic
const connectDB = async (retries = 5) => {
  for (let i = 0; i < retries; i++) {
    try {
      await mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
      console.log('MongoDB connected successfully');
      return true;
    } catch (error) {
      console.error(`Database connection attempt ${i + 1} failed:`, error);
      if (i === retries - 1) throw error;
      // Wait for 5 seconds before retrying
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }
};

// Graceful Shutdown
const gracefulShutdown = async () => {
  try {
    console.log('Initiating graceful shutdown...');
    
    // Close MongoDB connection
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
    
    // Clean up uploads directory
    if (fs.existsSync(uploadDir)) {
      const files = fs.readdirSync(uploadDir);
      for (const file of files) {
        fs.unlinkSync(path.join(uploadDir, file));
      }
      console.log('Temporary files cleaned up');
    }
    
    process.exit(0);
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
};

// Handle shutdown signals
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Start server with database connection
const startServer = async () => {
  try {
    await connectDB();
    
    const port = process.env.PORT || 3000;
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
      console.log('Upload directory initialized at:', uploadDir);
      console.log('Environment:', process.env.NODE_ENV || 'development');
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Initialize server
startServer();

// Export app for testing
module.exports = app;