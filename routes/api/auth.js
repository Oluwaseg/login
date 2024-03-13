const authController = require("../../controller/authController");
const {
  authenticateToken,
  checkSessionExpiration,
  verifyEmail,
} = require("../../middleware/authenticate");
const express = require("express");
const router = express.Router();

router.post(
  "/register",
  authController.upload.single("image"),
  authController.registerUser
);
router.post("/login", authController.loginUser);
router.post("/logout", authController.logoutUser);
router.post("/forgot-password", authController.forgotPassword);
router.post("/reset-password", authController.resetPassword);
router.post("/resend-verification", async (req, res) => {
  const { email } = req.body;
  const result = await authController.resendVerificationEmail(email);
  if (result.success) {
    const successMessage = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Success</title>
        <style>
          /* Add your CSS styles here */
          body {
            font-family: Arial, sans-serif;
            background-color: #f3f3f3;
            text-align: center;
          }
          .container {
            margin-top: 50px;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
          }
          h1 {
            color: #4caf50;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Success!</h1>
          <p>Verification email sent successfully. Check your email to verify.</p>
        </div>
        <script>
          // Show a toast notification
          alert("Verification email sent successfully. You will be redirected to login.");
          setTimeout(function() {
            window.location.href = "/api/login";
          }, 5000); // Redirect to login after 5 seconds
        </script>
      </body>
      </html>
    `;
    return res.send(successMessage);
  } else {
    const errorMessage = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Error</title>
        <style>
          /* Add your CSS styles here */
          body {
            font-family: Arial, sans-serif;
            background-color: #f3f3f3;
            text-align: center;
          }
          .container {
            margin-top: 50px;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
          }
          h1 {
            color: #f44336;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Error!</h1>
          <p>${result.message}</p>
          <button onclick="window.location.href='/api/login'" class="btn btn-primary">Go to Login</button>
        </div>
      </body>
      </html>
    `;
    return res.send(errorMessage);
  }
});

router.get("/register", (req, res) => {
  const successMsg = req.flash("success_msg");
  const errorMsg = req.flash("error_msg");
  res.render("register", {
    success_msg: successMsg,
    error_msg: errorMsg,
  });
});

router.get("/login", (req, res) => {
  const successMsg = req.flash("success_msg");
  const errorMsg = req.flash("error_msg");
  res.render("login", {
    success_msg: successMsg,
    error_msg: errorMsg,
  });
});
router.get("/home", authenticateToken, checkSessionExpiration, (req, res) => {
  const user = req.session.user;
  if (!user) {
    return res.redirect("/api/login");
  }
  res.render("layout", { user });
});
router.get("/forgot-password", (req, res) => {
  res.render("forgot-password");
});
router.get("/reset-password/:token", (req, res) => {
  const token = req.params.token;
  res.render("reset-password", { token });
});

router.get("/verify-email", verifyEmail);
router.get("/resend-verification", authenticateToken, (req, res) => {
  const user = req.session.user;
  if (!user) {
    // Handle case where user is not logged in
    return res.redirect("/api/login");
  }
  const email = user.email;
  res.render("resend-verification", { email });
});

router.get("/success", (req, res) => {
  res.render("success");
});

module.exports = router;
