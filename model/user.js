const mongoose = require("mongoose");
const slugify = require("slugify");
const crypto = require("crypto");

const schema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  image: {
    type: String,
  },
  tokens: [
    {
      type: String,
    },
  ],
  username: {
    type: String,
    unique: true,
  },
  verificationToken: String,
  isVerified: {
    type: Boolean,
    default: false,
  },
  resetPasswordToken: String,
});

schema.pre("save", async function (next) {
  // Check if the name field is modified or newly created
  if (this.isModified("name") || this.isNew) {
    // Extract the first 3 or 5 letters of the name
    const initials = this.name.substring(0, 3);
    // Generate a random number (e.g., between 1000 and 9999)
    const randomNumber = Math.floor(Math.random() * 9000) + 1000;
    // Concatenate the initials with the random number
    const randomUsername = `${initials}-${randomNumber}`;
    // Set the username field
    this.username = randomUsername;
  }
  next();
});

const User = mongoose.model("User", schema);

module.exports = User;
