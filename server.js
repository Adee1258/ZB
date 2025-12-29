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
const Product = require("./server/models/product.js");
const Order = require("./server/models/order.js");
const Contact = require("./server/models/contact.js");

const app = express();

// Middlewares
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
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

const adminPath = path.join(
  __dirname,
  "..",
  "zikriya-foods-frontend",
  "public",
  "admin"
);
console.log("Admin static path:", adminPath);
if (fs.existsSync(adminPath)) {
  console.log("Admin folder exists! Good.");
} else {
  console.log(
    "Admin folder NOT found! Check if 'zikriya-foods-frontend/public/admin' exists next to backend folder."
  );
}

const isServerless = !!process.env.VERCEL;
const uploadsPath = isServerless
  ? path.join("/tmp", "uploads")
  : path.join(__dirname, "public", "uploads");
console.log("Uploads path:", uploadsPath);
if (!fs.existsSync(uploadsPath)) {
  fs.mkdirSync(uploadsPath, { recursive: true });
  console.log("Created uploads folder in backend.");
}

const adminDpPath = isServerless
  ? path.join("/tmp", "admin-dp")
  : path.join(__dirname, "public", "admin-dp");
console.log("Admin DP path:", adminDpPath);
if (!fs.existsSync(adminDpPath)) {
  fs.mkdirSync(adminDpPath, { recursive: true });
  console.log("Created admin-dp folder in backend.");
}

const readProductsFallback = () => {
  try {
    const pjson = path.join(__dirname, "server", "data", "products.json");
    if (fs.existsSync(pjson)) {
      const data = fs.readFileSync(pjson, "utf-8");
      return JSON.parse(data);
    }
    return [];
  } catch {
    return [];
  }
};
// Multer for file uploads
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
    try {
      if (file.mimetype && file.mimetype.startsWith("image/")) {
        cb(null, true);
      } else {
        cb(new Error("Only image files are allowed"));
      }
    } catch (e) {
      cb(new Error("File filter error"));
    }
  },
});

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

app.get("/api/admin/profile", auth, async (req, res) => {
  try {
    let filename = "logo.jpeg";
    const filePath = path.join(adminDpPath, filename);
    if (!fs.existsSync(filePath)) {
      filename = null;
    }
    const username = "admin";
    const dp = filename ? "/admin-dp/" + filename : null;
    res.json({
      success: true,
      username,
      profilePicture: filename,
      dp,
    });
  } catch (err) {
    res.status(500).json({ success: false });
  }
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
      if (!name || !price || !stock) {
        return res
          .status(400)
          .json({ msg: "Name, price and stock are required" });
      }
      const numPrice = Number(price);
      const numStock = Number(stock);
      const numDiscount = discount ? Number(discount) : 0;
      if (Number.isNaN(numPrice) || Number.isNaN(numStock)) {
        return res.status(400).json({ msg: "Price and stock must be numbers" });
      }
      if (numDiscount < 0 || numDiscount > 100) {
        return res
          .status(400)
          .json({ msg: "Discount must be between 0 and 100" });
      }
      const images = req.files
        ? req.files.map((f) => "/uploads/" + f.filename)
        : [];

      const product = new Product({
        name,
        description,
        price: numPrice,
        discount: numDiscount || 0,
        stock: numStock,
        category,
        tags: tags ? JSON.parse(tags) : [],
        images,
      });

      await product.save();
      res.json({ msg: "Product added successfully!" });
    } catch (err) {
      console.error(err);
      res
        .status(500)
        .json({ msg: err.message || "Error adding product", error: true });
    }
  }
);

app.get("/api/admin/products", auth, async (req, res) => {
  try {
    if (mongoose.connection.readyState === 1) {
      const products = await Product.find().sort({ createdAt: -1 });
      return res.json(products);
    }
    const products = readProductsFallback();
    return res.json(products);
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
        price: price ? Number(price) : undefined,
        discount: discount ? Number(discount) : 0,
        stock: stock ? Number(stock) : undefined,
        category,
        tags: tags ? JSON.parse(tags) : [],
      };
      if (update.price !== undefined && Number.isNaN(update.price)) {
        return res.status(400).json({ msg: "Price must be a number" });
      }
      if (update.stock !== undefined && Number.isNaN(update.stock)) {
        return res.status(400).json({ msg: "Stock must be a number" });
      }
      if (update.discount < 0 || update.discount > 100) {
        return res
          .status(400)
          .json({ msg: "Discount must be between 0 and 100" });
      }

      if (req.files && req.files.length > 0) {
        update.images = req.files.map((f) => "/uploads/" + f.filename);
      }

      await Product.updateOne({ _id: req.params.id }, update);
      res.json({ msg: "Product updated successfully!" });
    } catch (err) {
      console.error(err);
      res
        .status(500)
        .json({ msg: err.message || "Error updating product", error: true });
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
    if (mongoose.connection.readyState === 1) {
      const products = await Product.find().sort({ createdAt: -1 });
      return res.json(products);
    }
    const products = readProductsFallback();
    res.json(products);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Error fetching products" });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    if (mongoose.connection.readyState === 1) {
      const product = await Product.findById(req.params.id);
      if (!product) return res.status(404).json({ msg: "Product not found" });
      return res.json(product);
    }
    const list = readProductsFallback();
    const item = list.find((p) => p._id === req.params.id);
    if (!item) return res.status(404).json({ msg: "Product not found" });
    res.json(item);
  } catch (err) {
    res.status(500).json({ msg: "Error fetching product" });
  }
});

// ====================== ADMIN ORDERS ======================
app.get("/api/admin/orders", auth, async (req, res) => {
  try {
    if (mongoose.connection.readyState === 1) {
      const orders = await Order.find().sort({ createdAt: -1 });
      return res.json(orders);
    }
    return res.json([]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Error fetching orders" });
  }
});

// ====================== PUBLIC ORDERS (Customer Order Creation) ======================
app.post("/api/orders", async (req, res) => {
  try {
    const { productId, buyer, qty, subtotal, total } = req.body;
    console.log("POST /api/orders", { productId, qty, subtotal, total });
    console.log("DB readyState:", mongoose.connection.readyState, "ObjectId.isValid:", mongoose.Types.ObjectId.isValid(productId));

    if (!productId || !buyer || !qty) {
      return res.status(400).json({ msg: "Missing required fields" });
    }

    const numQty = Number(qty);
    if (!Number.isFinite(numQty) || numQty <= 0) {
      return res.status(400).json({ msg: "Invalid quantity" });
    }

    if (mongoose.connection.readyState === 1 && mongoose.Types.ObjectId.isValid(productId)) {
      const product = await Product.findById(productId);
      if (!product) {
        return res.status(404).json({ msg: "Product not found" });
      }
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
      return res.json({
        msg: "Order created successfully!",
        order: newOrder,
        _id: newOrder._id,
      });
    } else {
      console.log("Orders fallback path (DB disconnected or invalid ID)");
      const list = readProductsFallback();
      const product = list.find((p) => p._id === productId);
      if (!product) {
        return res.status(404).json({ msg: "Product not found (fallback)" });
      }
      if (product.stock < numQty) {
        return res.status(400).json({ msg: "Insufficient stock (fallback)" });
      }
      const fakeId = "FAKE-" + Date.now().toString(36);
      const newOrder = {
        _id: fakeId,
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
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      return res.json({
        msg: "Order created successfully! (fallback, DB not connected)",
        order: newOrder,
        _id: newOrder._id,
      });
    }
  } catch (err) {
    console.error(err);
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
    if (mongoose.connection.readyState === 1) {
      const messages = await Contact.find().sort({ createdAt: -1 });
      return res.json(messages);
    }
    return res.json([]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Error fetching messages" });
  }
});

// Delete a contact message
app.delete("/api/admin/contact/:id", auth, async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res
        .status(503)
        .json({ msg: "Database not connected, cannot delete" });
    }
    const id = req.params.id;
    const deleted = await Contact.findByIdAndDelete(id);
    if (!deleted) {
      return res.status(404).json({ msg: "Message not found" });
    }
    res.json({ msg: "Message deleted", id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Error deleting message" });
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
if (process.env.VERCEL) {
  module.exports = (req, res) => app(req, res);
} else {
  app.listen(PORT, () => {
    console.log(`\nBACKEND SERVER RUNNING ON PORT ${PORT}`);
    console.log(`→ Admin Login: POST http://localhost:${PORT}/api/admin/login`);
    console.log(`→ Images: http://localhost:${PORT}/uploads/filename.jpg`);
    console.log(`→ Test Frontend: http://localhost:${PORT}/`);
    console.log(`→ Test Admin Login: http://localhost:${PORT}/admin/login.html`);
  });
}
