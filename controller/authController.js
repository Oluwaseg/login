const User = require("../model/user");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const jwt = require("jsonwebtoken");
const multer = require("multer");
const bcrypt = require("bcryptjs");
require("dotenv").config();
const secretKey = process.env.JWT_SECRET;

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/uploads/image");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 1024 * 1024 * 2 },
});

// Function to create a JWT token for a user
const createToken = (user) => {
  const tokenData = {
    userId: user._id,
    email: user.email,
    name: user.name,
    username: user.username,
    image: user.image,
  };

  const token = jwt.sign(tokenData, secretKey, { expiresIn: "30m" });

  return token;
};

// verify email
const sendVerificationEmail = (email, token) => {
  const verificationLink = `${process.env.CLIENT_URL}/api/verify-email?token=${token}`;

  // Send email with verification link
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USERNAME,
    to: email,
    subject: "Email Verification",
    html: `<div style="font-family: Arial, sans-serif;">
    <h1 style="color: #333;">Welcome to Our Website !</h1>

    <p>Thank you for registering with us. To complete your registration, please click the button below to verify your email:</p>
    <a href="${verificationLink}" style="background-color: #4CAF50; color: white; padding: 14px 20px; text-align: center; text-decoration: none; display: inline-block; border-radius: 4px; cursor: pointer;">Verify Email</a>
    <p>If you didn't register on our website, you can ignore this email.</p>
    <p>Best regards,<br/>Your Website Team</p>
  </div>`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
    } else {
      console.log("Email sent:", info.response);
    }
  });
};

const resendVerificationEmail = async (email) => {
  try {
    const user = await User.findOne({ email });

    if (!user) {
      return { success: false, message: "User not found" };
    }

    if (user.isVerified) {
      return { success: false, message: "User is already verified" };
    }

    const verificationToken = crypto.randomBytes(20).toString("hex");
    user.verificationToken = verificationToken;
    await user.save();

    sendVerificationEmail(user.email, verificationToken);

    return { success: true, message: "Verification email sent successfully" };
  } catch (error) {
    console.error("Error resending verification email:", error);
    return { success: false, message: "Internal Server Error" };
  }
};

const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({
      $or: [{ email: email }],
    });
    if (existingUser) {
      req.flash("error_msg", "Email already exists");
      return res.redirect("/api/register");
    }
    let imageUrl = "/uploads/profile/default.jpg";

    const profileImage = req.file;

    if (profileImage && profileImage.filename) {
      imageUrl = `/uploads/profile/images/${profileImage.filename}`;
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate verification token
    const verificationToken = crypto.randomBytes(20).toString("hex");

    const user = new User({
      name,
      email,
      password: hashedPassword,
      image: imageUrl,
      verificationToken: verificationToken,
    });

    const token = createToken(user);

    user.tokens.push(token);

    res.cookie("jwt", token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });

    await user.save();

    sendVerificationEmail(user.email, verificationToken);

    req.flash(
      "success_msg",
      "Registration successful. Please check your email to verify your account."
    );

    // Redirect to the registration page
    res.redirect("/api/register");
  } catch (error) {
    req.flash("error_msg", "Registration failed");
    res.redirect("/api/register");
    // res.status(500).json({ message: error.message });
    // console.error("Registration failed:", error);
  }
};

const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      req.flash("error_msg", "User not found");
      return res.redirect("/api/login");
    }
    if (!user.isVerified) {
      return res.redirect("/api/resend-verification");
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      req.flash("error_msg", "Invalid password");
      return res.redirect("/api/register");
    }

    // Password is valid, generate token
    const token = createToken(user);

    res.cookie("jwt", token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });
    req.session.user = user;
    res.redirect("/api/home");
  } catch (error) {
    // res.status(500).json({ message: error.message });

    req.flash("error_msg", "Login failed");
    res.redirect("/api/login");
  }
};

const logoutUser = async (req, res) => {
  try {
    // Get token from cookies
    const token = req.cookies.jwt;
    if (!token) {
      return res
        .status(401)
        .render("error", { status: 401, message: "User not authenticated" });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) {
      return res
        .status(401)
        .render("error", { status: 401, message: "Invalid token" });
    }

    // Clear cookie
    res.clearCookie("jwt");

    res.redirect("/api/login");
  } catch (error) {
    res.status(500).render("error", { status: 500, message: error.message });
    console.error("Logout failed:", error);
  }
};

const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    // Find user by email
    const user = await User.findOne({ email });

    if (!user) {
      return res
        .status(404)
        .render("error", { status: 404, message: "User not found" });
    }

    // Generate reset token
    const token = jwt.sign({ email }, process.env.RESET_PASSWORD_SECRET, {
      expiresIn: "15m", // Token expires in 15 minutes
    });

    user.resetPasswordToken = token;
    await user.save();
    // Send email with reset link
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USERNAME,
      to: email,
      subject: "Password Reset",
      html: `<p>You are receiving this email because you (or someone else) has requested the reset of the password for your account.</p>
            <p>Please click on the following link to reset your password. If you did not request this, please ignore this email and your password will remain unchanged.</p>
            <p><a href="${process.env.CLIENT_URL}/api/reset-password/${token}">Reset Password</a></p>`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending email:", error);
        return res
          .status(500)
          .render("error", { status: 500, message: "Failed to send email" });
      } else {
        console.log("Email sent:", info.response);
        res.send(`<!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Forgot Password Success</title>
      <!-- Bootstrap CSS -->
      <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css"
        rel="stylesheet"
      />
      <!-- Tailwind CSS -->
      <link
        href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css"
        rel="stylesheet"
      />
      <!-- Font Awesome -->
      <script src="https://kit.fontawesome.com/a076d05399.js"></script>
      <style>
        /* Center the modal vertically and horizontally */
        .modal {
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          padding: 0 10px;
        }

        /* Styling for modal content */
        .modal-content {
          background-color: #ffffff;
          border: 1px solid #ccc;
          border-radius: 8px;
          padding: 20px;
          max-width: 400px;
          width: 100%;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        /* Close button style */
        .close {
          color: #6b7280;
          font-size: 20px;
          cursor: pointer;
          position: absolute;
          top: 10px;
          right: 10px;
        }
      </style>
    </head>
    <body>
      <div class="modal">
        <div class="modal-content">
          <span class="close">&times;</span>
          <div class="text-center">
            <div class="text-green-500">
              <i class="fas fa-check-circle fa-5x"></i>
            </div>
            <h2 class="text-2xl font-bold text-gray-900 mt-4">
              Email Sent Successfully
            </h2>
            <p class="text-sm text-gray-600 mt-2">
              Please check your email for further instructions.
            </p>
          </div>
          <div class="flex justify-center mt-4">
            <button
              type="button"
              onclick="window.location.href = '/api/login';"
              class="w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700 focus:outline-none focus:bg-indigo-700"
            >
              Go to Login
            </button>
          </div>
        </div>
      </div>
    </body>
  </html>
  `);
      }
    });
  } catch (error) {
    console.error("Forgot password error:", error);
    return res
      .status(500)
      .render("error", { status: 500, message: "Internal Server Error" });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body;

    console.log("Received token:", token);
    const decodedToken = jwt.verify(token, process.env.RESET_PASSWORD_SECRET);

    console.log("Decoded token:", decodedToken);
    const user = await User.findOne({ email: decodedToken.email });

    if (!user) {
      return res
        .status(404)
        .render("error", { status: 404, message: "User not found" });
    }

    // Check if the resetPasswordToken matches the token provided
    if (user.resetPasswordToken !== token) {
      return res
        .status(401)
        .render("error", { status: 401, message: "Invalid token" });
    }

    if (typeof password !== "string") {
      return res.status(400).render("error", {
        status: 400,
        message: "Bad request: Password must be a string",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    user.password = hashedPassword;
    user.resetPasswordToken = null;
    await user.save();

    res.redirect("/api/success");
  } catch (error) {
    console.error("Reset password error:", error);
    return res
      .status(500)
      .render("error", { status: 500, message: "Internal Server Error" });
  }
};

module.exports = {
  registerUser,
  upload,
  loginUser,
  logoutUser,
  forgotPassword,
  resetPassword,
  resendVerificationEmail,
};
