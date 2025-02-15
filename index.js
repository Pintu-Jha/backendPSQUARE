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
app.use(cors());

// Create uploads directory with absolute path
const uploadDir = path.join(__dirname, 'uploads');
console.log('Upload directory path:', uploadDir); // Debug log
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Multer Storage Configuration
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function(req, file, cb) {
    // Sanitize the filename by removing special characters and spaces
    const originalName = file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
    const uniqueSuffix = Date.now() + '_' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '_' + originalName);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ["image/jpeg", "image/png", "image/jpg", "application/pdf"];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("Invalid file type. Only JPG, PNG, and PDF files are allowed."), false);
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: fileFilter
});

// MongoDB Schema (User & Uploads)
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  prescriptions: [{
    uploadId: mongoose.Schema.Types.ObjectId,
    url: String,
    uploadDate: Date,
    type: String,
  }],
});
const User = mongoose.model("User", userSchema);

const uploadSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  type: { type: String, enum: ["file", "link"], required: true },
  url: { type: String, required: true },
  originalName: String,
  mimeType: String,
  size: Number,
  uploadDate: { type: Date, default: Date.now },
  status: { type: String, enum: ["pending", "completed", "failed"], default: "pending" },
});
const Upload = mongoose.model("Upload", uploadSchema);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  try {
    const token = req.headers["authorization"]?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Access token required" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ message: "Invalid or expired token" });
      }
      req.user = user;
      next();
    });
  } catch (error) {
    return res.status(401).json({ message: "Authentication error", error: error.message });
  }
};

// User Signup
app.post("/api/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists" });
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
    res.status(500).json({ message: "Error creating user", error: error.message });
  }
});

// User Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
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
    res.status(500).json({ message: "Error logging in", error: error.message });
  }
});

// File Upload Endpoint
app.post("/api/upload/file", authenticateToken, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "No file uploaded" });

    console.log("File saved at:", req.file.path); // Debugging line

    const result = await cloudinary.uploader.upload(req.file.path, { resource_type: "auto", folder: "prescriptions" });

    const upload = new Upload({ 
      userId: req.user.userId, 
      type: "file", 
      url: result.secure_url, 
      originalName: req.file.originalname, 
      mimeType: req.file.mimetype, 
      size: req.file.size, 
      status: "completed" 
    });
    await upload.save();

    res.json({ message: "File uploaded", upload });
  } catch (error) {
    res.status(500).json({ message: "Error uploading file", error: error.message });
  }
});
// Upload Link
app.post("/api/upload/link", authenticateToken, [
  body('url').isURL().withMessage('Please provide a valid URL')
    .matches(/\.(jpg|jpeg|png|pdf)$/i).withMessage('URL must point to a JPG, PNG or PDF file')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { url } = req.body;

    const upload = new Upload({
      userId: req.user.userId,
      type: "link",
      url: url,
      status: "completed"
    });

    await upload.save();

    await User.findByIdAndUpdate(req.user.userId, {
      $push: {
        prescriptions: {
          uploadId: upload._id,
          url: url,
          uploadDate: new Date(),
          type: 'link'
        }
      }
    });

    res.json({
      message: "Link uploaded successfully",
      upload: {
        id: upload._id,
        url: url,
        type: 'link'
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Error processing link upload", error: error.message });
  }
});

// Get Uploads
app.get("/api/uploads", authenticateToken, async (req, res) => {
  try {
    const uploads = await Upload.find({ userId: req.user.userId })
      .sort({ uploadDate: -1 });
    res.json({ uploads });
  } catch (error) {
    res.status(500).json({ message: "Error fetching uploads", error: error.message });
  }
});

// Delete Upload
app.delete("/api/uploads/:uploadId", authenticateToken, async (req, res) => {
  try {
    const upload = await Upload.findOne({
      _id: req.params.uploadId,
      userId: req.user.userId
    });

    if (!upload) {
      return res.status(404).json({ message: "Upload not found" });
    }

    // Delete from Cloudinary if it's a file
    if (upload.type === "file") {
      const publicId = `prescriptions/${path.basename(upload.url.split('/').pop(), path.extname(upload.url))}`;
      await cloudinary.uploader.destroy(publicId);
    }

    // Remove from user's prescriptions
    await User.findByIdAndUpdate(req.user.userId, {
      $pull: {
        prescriptions: { uploadId: upload._id }
      }
    });

    // Delete the upload record
    await upload.deleteOne();

    res.json({ message: "Upload deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting upload", error: error.message });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Error:', error);
  if (error instanceof multer.MulterError) {
    return res.status(400).json({
      message: "File upload error",
      error: error.message
    });
  }
  res.status(500).json({
    message: "Internal server error",
    error: error.message
  });
});

// Connect to MongoDB & Start Server
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    app.listen(process.env.PORT || 3000, () => {
      console.log(`Server running on port ${process.env.PORT || 3000}`);
      console.log('Upload directory initialized at:', uploadDir);
    });
  })
  .catch(error => {
    console.error("Database connection error:", error);
  });