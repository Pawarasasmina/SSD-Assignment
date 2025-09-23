const express = require("express");
const router = express.Router();

const { body, param, validationResult } = require('express-validator');

const cartProduct = require("../models/cartProduct");


// Validation middleware
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Validation for cart product ID parameter
const validateCartProductId = [
  param('id').isMongoId().withMessage('Invalid cart product ID format'),
  validateRequest
];

// Validation for user ID parameter
const validateUserId = [
  param('userId').isString().trim().notEmpty().withMessage('User ID is required'),
  validateRequest
];



router.get("/test", (req, res) => res.send("route is working"));

// Add cart product
router.post("/", (req, res) =>
  cartProduct
    .create(req.body)
    .then(() => res.json({ msg: "Successfully added to the cart" }))
    .catch(() => res.status(400).json({ msg: "Cart adding failed" }))
);

// Get all cart products
router.get("/", (req, res) =>
  cartProduct
    .find(req.body)
    .then((cartProducts) => res.json(cartProducts))
    .catch(() => res.status(400).json({ msg: "CartItems getting failed" }))
);

// Get cart items by ID
router.get("/:id", (req, res) =>
  cartProduct
    .findById(req.params.id)
    .then((cartProduct) => res.json(cartProduct))
    .catch(() => res.status(400).json({ msg: "CartItems getting by id failed" }))
);

// Get cart items by userId with validation
router.get("/user/:userId", validateUserId, (req, res) =>
  cartProduct
    .find({ userId: req.params.userId })
    .then((cartProducts) => res.json(cartProducts))
    .catch((error) => res.status(400).json({ 
      msg: "Fetching cart items by userId failed", 
      error: error.message 
    }))
);

// Update cart item by ID with validation
router.put("/:id", validateCartProductId, (req, res) =>
  cartProduct
    .findByIdAndUpdate(req.params.id, req.body)
    .then(() => res.json({ msg: "CartItems updated successfully" }))
    .catch((error) => res.status(400).json({ 
      msg: "CartItems update failed", 
      error: error.message 
    }))
);

// Delete cart item by ID
router.delete("/:id", (req, res) =>
  cartProduct
    .findByIdAndDelete(req.params.id)
    .then(() => res.json({ msg: "CartItems deleted successfully" }))
    .catch(() => res.status(400).json({ msg: "CartItems delete failed" }))
);

// Delete multiple cart items
router.delete("/", (req, res) => {
  const ids = req.body.ids; // Retrieve the IDs from the request body

  if (!ids || !Array.isArray(ids)) {
    return res.status(400).json({ msg: "Invalid request data" });
  }

  cartProduct
    .deleteMany({ _id: { $in: ids } })
    .then(() => res.json({ msg: "Selected items deleted successfully" }))
    .catch((err) =>
      res.status(400).json({ msg: "Failed to delete selected items", error: err })
    );
});

module.exports = router;
