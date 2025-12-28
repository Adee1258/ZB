const mongoose = require("mongoose");

const orderSchema = new mongoose.Schema({
  productId: String,
  productName: String,
  buyer: {
    name: String,
    phone: String,
    address: String,
  },
  qty: Number,
  subtotal: Number,
  gst: Number,
  delivery: Number,
  total: Number,
  status: { type: String, default: "Pending" },
  createdAt: { type: Date, default: Date.now },
  updatedAt: Date,
});

module.exports = mongoose.model("Order", orderSchema);
