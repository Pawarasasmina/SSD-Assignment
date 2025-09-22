const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  id: { type: String, unique: true }, // Custom ID
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // Keep password as plain text
  phone: { type: String },
  userLevel: { type: Number, default: 0 }, // 0: Customer, 1: Seller, 2: Admin
  shopId: { type: String, default: null }, // Only for sellers
});

// Hash password before saving
userSchema.pre("save", async function (next) {
  // Only hash the password if it's modified (or new)
  if (!this.isModified("password")) return next();
  
  try {
    // Generate a salt with cost factor 10
    const salt = await bcrypt.genSalt(10);
    // Hash the password with the salt
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Add method to compare password for login
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};


// Utility function to generate the custom ID
const generateCustomId = async function (userLevel, shopId) {
  let prefix = "";

  if (userLevel === 2) {
    // For Admins
    prefix = "A";
  } else if (userLevel === 1 && shopId) {
    // For Sellers, use shopId in the format S_shopId001
    prefix = `S_${shopId}`;
  } else {
    // For Customers
    prefix = "C";
  }

  // Get the next count of users for this role type
  const count = await User.countDocuments({ userLevel });
  const nextNumber = (count + 1).toString().padStart(3, "0"); // e.g., 001, 002, etc.

  return `${prefix}${nextNumber}`;
};

// Pre-save hook to generate ID
userSchema.pre("save", async function (next) {
  if (this.isNew) {
    this.id = await generateCustomId(this.userLevel, this.shopId);
  }
  next();
});

const User = mongoose.model("User", userSchema);

module.exports = User;
