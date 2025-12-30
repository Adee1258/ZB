require("dotenv").config();
const express = require("express");
const multer = require("multer");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");
const mongoose = require("mongoose");

// Models
const Product = require("./server/models/product.js");
const Order = require("./server/models/order.js");
const Contact = require("./server/models/contact.js");

const app = express();

// ===== CORS - Allow requests from frontend =====
app.use(
  cors({
    origin: [
      "https://www.zdspices.pk",
      "https://zdspices.pk",
      "http://localhost:3000",
      "http://localhost:5000",
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
    preflightContinue: false,
    optionsSuccessStatus: 204,
  })
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));
app.options("*", cors());

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// MongoDB Connection with retry
let isConnected = false;

const connectDB = async () => {
  if (isConnected) return;

  try {
    if (!process.env.MONGO_URI) {
      console.warn("MONGO_URI not set - using mock data");
      return;
    }

    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      retryWrites: true,
      w: "majority",
    });

    isConnected = true;
    console.log("✅ MongoDB Connected!");
  } catch (err) {
    console.error("⚠️ MongoDB Connection Error:", err.message);
    console.log("Continuing with fallback...");
  }
};

connectDB();

// Admin User
let users = [];
const initAdmin = async () => {
  if (users.length === 0) {
    const hashed = await bcrypt.hash("admin123", 10);
    users.push({
      _id: "1",
      username: "admin",
      password: hashed,
    });
    console.log("✅ Admin created → username: admin, password: admin123");
  }
};
initAdmin();

// ===== IMAGE STORAGE - Base64 in MongoDB =====
const storage = multer.memoryStorage();

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype && file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only images allowed"));
    }
  },
});

// JWT Auth Middleware
const auth = (req, res, next) => {
  let token = req.header("Authorization");
  if (token && token.startsWith("Bearer ")) token = token.slice(7);
  if (!token) return res.status(401).json({ msg: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "fallback");
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ msg: "Invalid token" });
  }
};

// Helper function to convert buffer to base64
const bufferToBase64 = (buffer, mimetype) => {
  return `data:${mimetype};base64,${buffer.toString("base64")}`;
};

// ====================== API ROUTES ======================

// Health check
app.get("/", (req, res) => {
  res.json({
    status: "ok",
    message: "ZIKRIYA DARBAR Backend API Running",
    endpoints: {
      products: "/api/products",
      admin: "/api/admin/login",
    },
  });
});

app.get("/api", (req, res) => {
  res.json({ status: "API Working", version: "1.0" });
});

// ===== ADMIN LOGIN =====
app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ msg: "Username and password required" });
    }

    const user = users.find((u) => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET || "fallback",
      { expiresIn: "7d" }
    );

    res.json({ token, msg: "Login successful" });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ msg: "Login error" });
  }
});

app.get("/api/admin/profile", auth, async (req, res) => {
  try {
    res.json({
      success: true,
      username: "admin",
      profilePicture: "logo.jpeg",
      dp: null,
    });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

// ===== ADMIN PRODUCTS =====
app.post(
  "/api/admin/products",
  auth,
  upload.array("images", 5),
  async (req, res) => {
    try {
      const { name, description, price, discount, stock, category, tags } =
        req.body;

      if (!name || !price || stock === undefined) {
        return res.status(400).json({ msg: "Name, price and stock required" });
      }

      const numPrice = Number(price);
      const numStock = Number(stock);
      const numDiscount = discount ? Number(discount) : 0;

      if (isNaN(numPrice) || isNaN(numStock)) {
        return res.status(400).json({ msg: "Price and stock must be numbers" });
      }

      // Convert uploaded images to base64
      const images = req.files
        ? req.files.map((file) => bufferToBase64(file.buffer, file.mimetype))
        : [];

      // Generate SKU
      const sku = `SKU-${Date.now()}`;

      const product = new Product({
        name: name.trim(),
        description: description ? description.trim() : "",
        price: numPrice,
        discount: numDiscount,
        stock: numStock,
        category: category || "General",
        tags: tags ? (typeof tags === "string" ? JSON.parse(tags) : tags) : [],
        images,
        sku,
      });

      await product.save();
      console.log("✅ Product added:", product._id);
      res.json({ msg: "Product added successfully!", product });
    } catch (err) {
      console.error("Add product error:", err);
      res.status(500).json({ msg: err.message || "Error adding product" });
    }
  }
);

app.get("/api/admin/products", auth, async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (err) {
    console.error("Fetch products error:", err);
    res.status(500).json({ msg: "Error fetching products" });
  }
});

app.get("/api/admin/products/:id", auth, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ msg: "Not found" });
    res.json(product);
  } catch (err) {
    console.error("Fetch single product error:", err);
    res.status(500).json({ msg: "Error fetching product" });
  }
});

app.put(
  "/api/admin/products/:id",
  auth,
  upload.array("images", 5),
  async (req, res) => {
    try {
      const { name, description, price, discount, stock, category, tags } =
        req.body;

      const update = {};

      if (name) update.name = name.trim();
      if (description) update.description = description.trim();
      if (price) update.price = Number(price);
      if (discount) update.discount = Number(discount);
      if (stock !== undefined) update.stock = Number(stock);
      if (category) update.category = category;
      if (tags) {
        update.tags = typeof tags === "string" ? JSON.parse(tags) : tags;
      }

      // Convert new images to base64
      if (req.files && req.files.length > 0) {
        update.images = req.files.map((file) =>
          bufferToBase64(file.buffer, file.mimetype)
        );
      }

      await Product.findByIdAndUpdate(req.params.id, update, { new: true });
      console.log("✅ Product updated:", req.params.id);
      res.json({ msg: "Product updated!" });
    } catch (err) {
      console.error("Update product error:", err);
      res.status(500).json({ msg: err.message || "Error updating" });
    }
  }
);

app.delete("/api/admin/products/:id", auth, async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    console.log("✅ Product deleted:", req.params.id);
    res.json({ msg: "Product deleted!" });
  } catch (err) {
    console.error("Delete product error:", err);
    res.status(500).json({ msg: "Error deleting" });
  }
});

// ===== PUBLIC PRODUCTS =====
app.get("/api/products", async (req, res) => {
  try {
    console.log("📡 Fetching products from database...");

    const products = await Product.find().sort({ createdAt: -1 });

    if (!products || products.length === 0) {
      console.log("⚠️ No products found, returning empty array");
      return res.json([]);
    }

    console.log(`✅ Found ${products.length} products`);
    res.json(products);
  } catch (err) {
    console.error("❌ Error fetching products:", err.message);
    res.status(500).json({
      msg: "Error fetching products",
      error: err.message,
    });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ msg: "Product not found" });
    res.json(product);
  } catch (err) {
    console.error("Fetch single product error:", err);
    res.status(500).json({ msg: "Error fetching product" });
  }
});

// ===== ORDERS =====
app.get("/api/admin/orders", auth, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    console.error("Fetch orders error:", err);
    res.status(500).json({ msg: "Error fetching orders" });
  }
});

app.post("/api/orders", async (req, res) => {
  try {
    const { productId, buyer, qty, subtotal, total } = req.body;

    if (!productId || !buyer || !qty) {
      return res.status(400).json({ msg: "Missing required fields" });
    }

    const numQty = Number(qty);
    if (!isFinite(numQty) || numQty <= 0) {
      return res.status(400).json({ msg: "Invalid quantity" });
    }

    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ msg: "Product not found" });

    if (product.stock < numQty) {
      return res.status(400).json({
        msg: `Insufficient stock. Only ${product.stock} available`,
      });
    }

    const newOrder = new Order({
      productId,
      productName: product.name,
      buyer: {
        name: buyer.name,
        phone: buyer.phone,
        address: buyer.address,
      },
      qty: numQty,
      subtotal: subtotal || 0,
      total: total || 0,
      status: "Pending",
    });

    await newOrder.save();

    product.stock -= numQty;
    await product.save();

    console.log("✅ Order created:", newOrder._id);
    res.json({ msg: "Order created!", order: newOrder });
  } catch (err) {
    console.error("Create order error:", err);
    res.status(500).json({ msg: "Error creating order" });
  }
});

app.put("/api/admin/orders/:id", auth, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ msg: "Order not found" });

    const oldStatus = order.status;
    order.status = req.body.status || order.status;
    order.updatedAt = new Date();

    if (req.body.status === "Rejected" && oldStatus === "Pending") {
      const product = await Product.findById(order.productId);
      if (product) {
        product.stock += order.qty;
        await product.save();
      }
    }

    await order.save();
    console.log("✅ Order status updated:", order._id);
    res.json({ msg: "Status updated!", order });
  } catch (err) {
    console.error("Update order error:", err);
    res.status(500).json({ msg: "Error updating order" });
  }
});

// ===== CONTACT =====
app.get("/api/admin/contact", auth, async (req, res) => {
  try {
    const messages = await Contact.find().sort({ createdAt: -1 });
    res.json(messages);
  } catch (err) {
    console.error("Fetch contact messages error:", err);
    res.status(500).json({ msg: "Error fetching messages" });
  }
});

app.delete("/api/admin/contact/:id", auth, async (req, res) => {
  try {
    const deleted = await Contact.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ msg: "Not found" });
    res.json({ msg: "Deleted", id: req.params.id });
  } catch (err) {
    console.error("Delete contact error:", err);
    res.status(500).json({ msg: "Error deleting" });
  }
});

app.post("/api/contact", async (req, res) => {
  try {
    const { name, phone, email, message } = req.body;

    if (!name || !phone || !message) {
      return res.status(400).json({ msg: "Name, phone, message required" });
    }

    const newMsg = new Contact({
      name: name.trim(),
      phone: phone.trim(),
      email: email ? email.trim() : "",
      message: message.trim(),
    });

    await newMsg.save();
    console.log("✅ Contact message saved");
    res.json({ msg: "Message sent successfully!" });
  } catch (err) {
    console.error("Contact error:", err);
    res.status(500).json({ msg: "Error sending message" });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ msg: "Endpoint not found", path: req.path });
});

// Error handler
app.use((err, req, res, next) => {
  console.error("Global error:", err);
  res.status(500).json({
    msg: "Server error",
    error: process.env.NODE_ENV === "development" ? err.message : undefined,
  });
});

// Start server
const PORT = process.env.PORT || 5000;

if (process.env.VERCEL) {
  module.exports = app;
} else {
  app.listen(PORT, () => {
    console.log(`\n🚀 ZIKRIYA DARBAR BACKEND RUNNING ON PORT ${PORT}`);
    console.log(`📍 Test API: http://localhost:${PORT}/api/products`);
    console.log(`📍 Admin Login: http://localhost:${PORT}/api/admin/login`);
    console.log(`📍 API Health: http://localhost:${PORT}/api\n`);
  });
}
