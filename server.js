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
app.options("*", cors());

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected!"))
  .catch((err) => console.error("❌ MongoDB Error:", err));

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

// ===== UPLOADS PATH (Backend only needs this for image uploads) =====
const isServerless = !!process.env.VERCEL;
const uploadsPath = isServerless
  ? path.join("/tmp", "uploads")
  : path.join(__dirname, "uploads");

console.log("📁 Uploads path:", uploadsPath);
if (!fs.existsSync(uploadsPath)) {
  fs.mkdirSync(uploadsPath, { recursive: true });
  console.log("✅ Created uploads folder");
}

const adminDpPath = isServerless
  ? path.join("/tmp", "admin-dp")
  : path.join(__dirname, "admin-dp");

console.log("📁 Admin DP path:", adminDpPath);
if (!fs.existsSync(adminDpPath)) {
  fs.mkdirSync(adminDpPath, { recursive: true });
  console.log("✅ Created admin-dp folder");
}

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const fullPath = req.body.type === "dp" ? adminDpPath : uploadsPath;
    if (!fs.existsSync(fullPath)) {
      fs.mkdirSync(fullPath, { recursive: true });
    }
    cb(null, fullPath);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({
  storage,
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
  const { username, password } = req.body;
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
});

app.get("/api/admin/profile", auth, async (req, res) => {
  try {
    let filename = "logo.jpeg";
    const filePath = path.join(adminDpPath, filename);
    if (!fs.existsSync(filePath)) filename = null;

    res.json({
      success: true,
      username: "admin",
      profilePicture: filename,
      dp: filename ? "/admin-dp/" + filename : null,
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

      if (!name || !price || !stock) {
        return res.status(400).json({ msg: "Name, price and stock required" });
      }

      const numPrice = Number(price);
      const numStock = Number(stock);
      const numDiscount = discount ? Number(discount) : 0;

      if (Number.isNaN(numPrice) || Number.isNaN(numStock)) {
        return res.status(400).json({ msg: "Price and stock must be numbers" });
      }

      const images = req.files
        ? req.files.map((f) => "/uploads/" + f.filename)
        : [];

      const product = new Product({
        name,
        description,
        price: numPrice,
        discount: numDiscount,
        stock: numStock,
        category,
        tags: tags ? JSON.parse(tags) : [],
        images,
      });

      await product.save();
      res.json({ msg: "Product added successfully!" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ msg: err.message || "Error adding product" });
    }
  }
);

app.get("/api/admin/products", auth, async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (err) {
    res.status(500).json({ msg: "Error fetching products" });
  }
});

app.get("/api/admin/products/:id", auth, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ msg: "Not found" });
    res.json(product);
  } catch (err) {
    res.status(500).json({ msg: "Error" });
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

      const update = {
        name,
        description,
        price: price ? Number(price) : undefined,
        discount: discount ? Number(discount) : 0,
        stock: stock ? Number(stock) : undefined,
        category,
        tags: tags ? JSON.parse(tags) : [],
      };

      if (req.files && req.files.length > 0) {
        update.images = req.files.map((f) => "/uploads/" + f.filename);
      }

      await Product.updateOne({ _id: req.params.id }, update);
      res.json({ msg: "Product updated!" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ msg: err.message || "Error updating" });
    }
  }
);

app.delete("/api/admin/products/:id", auth, async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ msg: "Product deleted!" });
  } catch (err) {
    res.status(500).json({ msg: "Error deleting" });
  }
});

// ===== PUBLIC PRODUCTS =====
app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Error fetching products" });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ msg: "Not found" });
    res.json(product);
  } catch (err) {
    res.status(500).json({ msg: "Error" });
  }
});

// ===== ORDERS =====
app.get("/api/admin/orders", auth, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ msg: "Error fetching orders" });
  }
});

app.post("/api/orders", async (req, res) => {
  try {
    const { productId, buyer, qty, subtotal, total } = req.body;

    if (!productId || !buyer || !qty) {
      return res.status(400).json({ msg: "Missing fields" });
    }

    const numQty = Number(qty);
    if (!Number.isFinite(numQty) || numQty <= 0) {
      return res.status(400).json({ msg: "Invalid quantity" });
    }

    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ msg: "Product not found" });

    if (product.stock < numQty) {
      return res.status(400).json({ msg: "Insufficient stock" });
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
      subtotal,
      total,
      status: "Pending",
    });

    await newOrder.save();
    product.stock -= numQty;
    await product.save();

    res.json({ msg: "Order created!", order: newOrder });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Error creating order" });
  }
});

app.put("/api/admin/orders/:id", auth, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ msg: "Not found" });

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
    res.json({ msg: "Status updated!", order });
  } catch (err) {
    res.status(500).json({ msg: "Error updating" });
  }
});

// ===== CONTACT =====
app.get("/api/admin/contact", auth, async (req, res) => {
  try {
    const messages = await Contact.find().sort({ createdAt: -1 });
    res.json(messages);
  } catch (err) {
    res.status(500).json({ msg: "Error fetching messages" });
  }
});

app.delete("/api/admin/contact/:id", auth, async (req, res) => {
  try {
    const deleted = await Contact.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ msg: "Not found" });
    res.json({ msg: "Deleted", id: req.params.id });
  } catch (err) {
    res.status(500).json({ msg: "Error deleting" });
  }
});

app.post("/api/contact", async (req, res) => {
  try {
    const { name, phone, email, message } = req.body;
    if (!name || !phone || !message) {
      return res.status(400).json({ msg: "Name, phone, message required" });
    }
    const newMsg = new Contact({ name, phone, email, message });
    await newMsg.save();
    res.json({ msg: "Message sent!" });
  } catch (err) {
    res.status(500).json({ msg: "Error sending message" });
  }
});

// ===== SERVE UPLOADED FILES =====
app.use("/uploads", express.static(uploadsPath));
app.use("/admin-dp", express.static(adminDpPath));

// 404 handler
app.use((req, res) => {
  res.status(404).json({ msg: "Endpoint not found" });
});

// Start server
const PORT = process.env.PORT || 5000;
if (process.env.VERCEL) {
  module.exports = (req, res) => app(req, res);
} else {
  app.listen(PORT, () => {
    console.log(`\n🚀 BACKEND API RUNNING ON PORT ${PORT}`);
    console.log(`→ Test: http://localhost:${PORT}/api/products`);
  });
}
