require("dotenv").config();
const express = require("express");
const multer = require("multer");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");
const mongoose = require("mongoose");

// Models (case-sensitive filenames ke hisab se)
const Product = require("./server/models/Product.js");
const Order = require("./server/models/Order.js");
const Contact = require("./server/models/Contact.js");

const app = express();

// Middlewares
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "10mb" }));

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected Successfully!"))
  .catch((err) => console.error("MongoDB Error:", err));

// Hardcoded Admin User
let users = [];
const initAdmin = async () => {
  if (users.length === 0) {
    const hashed = await bcrypt.hash("admin123", 10);
    users.push({
      _id: "1",
      username: "admin",
      password: hashed,
    });
    console.log("Admin created → username: admin, password: admin123");
  }
};
initAdmin();

// Debug: Print static paths to check if folders exist
const publicPath = path.join(
  __dirname,
  "..",
  "zikriya-foods-frontend",
  "public"
);
console.log("Public static path:", publicPath);
if (fs.existsSync(publicPath)) {
  console.log("Public folder exists! Good.");
} else {
  console.log(
    "Public folder NOT found! Check if 'zikriya-foods-frontend/public' exists next to backend folder."
  );
}

const adminPath = path.join(__dirname, "..", "zikriya-foods-frontend", "admin");
console.log("Admin static path:", adminPath);
if (fs.existsSync(adminPath)) {
  console.log("Admin folder exists! Good.");
} else {
  console.log(
    "Admin folder NOT found! Check if 'zikriya-foods-frontend/admin' exists next to backend folder."
  );
}

const uploadsPath = path.join(__dirname, "public", "uploads");
console.log("Uploads path:", uploadsPath);
if (!fs.existsSync(uploadsPath)) {
  fs.mkdirSync(uploadsPath, { recursive: true });
  console.log("Created uploads folder in backend.");
}

const adminDpPath = path.join(__dirname, "public", "admin-dp");
console.log("Admin DP path:", adminDpPath);
if (!fs.existsSync(adminDpPath)) {
  fs.mkdirSync(adminDpPath, { recursive: true });
  console.log("Created admin-dp folder in backend.");
}

// Multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dest = req.body.type === "dp" ? "public/admin-dp" : "public/uploads";
    const fullPath = path.join(__dirname, dest);
    if (!fs.existsSync(fullPath)) {
      fs.mkdirSync(fullPath, { recursive: true });
    }
    cb(null, fullPath);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage });

// JWT Auth Middleware
const auth = (req, res, next) => {
  let token = req.header("Authorization");
  if (token && token.startsWith("Bearer ")) token = token.slice(7);
  if (!token) return res.status(401).json({ msg: "No token, access denied" });

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "fallbacksecret"
    );
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ msg: "Token is not valid" });
  }
};

// ====================== ADMIN LOGIN ONLY (profile removed) ======================
app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ msg: "Invalid credentials" });
  }
  const token = jwt.sign(
    { id: user._id },
    process.env.JWT_SECRET || "fallbacksecret",
    {
      expiresIn: "7d",
    }
  );
  res.json({ token, msg: "Login successful" });
});

// ====================== ADMIN PRODUCTS CRUD ======================
app.post(
  "/api/admin/products",
  auth,
  upload.array("images", 5),
  async (req, res) => {
    try {
      const { name, description, price, discount, stock, category, tags } =
        req.body;
      const images = req.files
        ? req.files.map((f) => "/uploads/" + f.filename)
        : [];

      const product = new Product({
        name,
        description,
        price,
        discount: discount || 0,
        stock,
        category,
        tags: tags ? JSON.parse(tags) : [],
        images,
      });

      await product.save();
      res.json({ msg: "Product added successfully!" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ msg: "Error adding product" });
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
    if (!product) return res.status(404).json({ msg: "Product not found" });
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
        price,
        discount: discount || 0,
        stock,
        category,
        tags: tags ? JSON.parse(tags) : [],
      };

      if (req.files && req.files.length > 0) {
        update.images = req.files.map((f) => "/uploads/" + f.filename);
      }

      await Product.updateOne({ _id: req.params.id }, update);
      res.json({ msg: "Product updated successfully!" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ msg: "Error updating product" });
    }
  }
);

app.delete("/api/admin/products/:id", auth, async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ msg: "Product deleted successfully!" });
  } catch (err) {
    res.status(500).json({ msg: "Error deleting product" });
  }
});

// ====================== PUBLIC PRODUCTS (for frontend display) ======================
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
    if (!product) return res.status(404).json({ msg: "Product not found" });
    res.json(product);
  } catch (err) {
    res.status(500).json({ msg: "Error fetching product" });
  }
});

// ====================== ADMIN ORDERS ======================
app.get("/api/admin/orders", auth, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Error fetching orders" });
  }
});

// ====================== PUBLIC ORDERS (Customer Order Creation) ======================
app.post("/api/orders", async (req, res) => {
  try {
    const { productId, buyer, qty, subtotal, total } = req.body;

    if (!productId || !buyer || !qty) {
      return res.status(400).json({ msg: "Missing required fields" });
    }

    // Check product stock
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ msg: "Product not found" });
    }

    if (product.stock < qty) {
      return res.status(400).json({ msg: "Insufficient stock" });
    }

    // Create order
    const newOrder = new Order({
      productId,
      productName: product.name,
      buyer: {
        name: buyer.name,
        phone: buyer.phone,
        address: buyer.address,
      },
      qty,
      subtotal,
      total,
      status: "Pending",
    });

    await newOrder.save();

    // Reduce stock
    product.stock -= qty;
    await product.save();

    res.json({
      msg: "Order created successfully!",
      order: newOrder,
      _id: newOrder._id,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Error creating order" });
  }
});

app.get("/api/admin/orders", auth, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Error fetching orders" });
  }
});

app.put("/api/admin/orders/:id", auth, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ msg: "Order not found" });

    const oldStatus = order.status;
    order.status = req.body.status || order.status;
    order.updatedAt = new Date();

    // Stock restore on rejection
    if (req.body.status === "Rejected" && oldStatus === "Pending") {
      const product = await Product.findById(order.productId);
      if (product) {
        product.stock += order.qty;
        await product.save();
      }
    }

    await order.save();
    res.json({ msg: "Order status updated!", order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Error updating order" });
  }
});

// ====================== ADMIN CONTACT MESSAGES ======================
app.get("/api/admin/contact", auth, async (req, res) => {
  try {
    const messages = await Contact.find().sort({ createdAt: -1 });
    res.json(messages);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Error fetching messages" });
  }
});

// ====================== PUBLIC CONTACT FORM ======================
app.post("/api/contact", async (req, res) => {
  try {
    const { name, phone, email, message } = req.body;
    if (!name || !phone || !message) {
      return res
        .status(400)
        .json({ msg: "Name, phone and message are required" });
    }
    const newMsg = new Contact({ name, phone, email, message });
    await newMsg.save();
    res.json({ msg: "Message sent successfully!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Error sending message" });
  }
});

// Serve static files
app.use("/uploads", express.static(uploadsPath));
app.use("/admin-dp", express.static(adminDpPath));

// Serve frontend public files
app.use(express.static(publicPath));

// Serve admin files
app.use("/admin", express.static(adminPath));

// Explicit root route for index.html (extra safety)
app.get("/", (req, res) => {
  const indexPath = path.join(publicPath, "index.html");
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send("Index file not found");
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ msg: "API endpoint not found" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\nBACKEND SERVER RUNNING ON PORT ${PORT}`);
  console.log(`→ Admin Login: POST http://localhost:${PORT}/api/admin/login`);
  console.log(`→ Images: http://localhost:${PORT}/uploads/filename.jpg`);
  console.log(`→ Test Frontend: http://localhost:${PORT}/`);
  console.log(`→ Test Admin Login: http://localhost:${PORT}/admin/login.html`);
});
