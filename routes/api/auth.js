const express = require("express");
const authController = require("../../controller/authController");
const {
  authenticateToken,
  checkSessionExpiration,
  verifyEmail,
} = require("../../middleware/authenticate");
const upload = require("../../middleware/image.config");
const router = express.Router();

router.post("/register", upload.single("image"), authController.registerUser);
router.post("/login", authController.loginUser);
router.post("/logout", authController.logoutUser);
router.post("/forgot-password", authController.forgotPassword);
router.post("/reset-password", authController.resetPassword);
router.post("/resend-verification", async (req, res) => {
  const { email } = req.body;
  const result = await authController.resendVerificationEmail(email);
  if (result.success) {
    return res.status(200).json({
      message:
        "Verification email sent successfully. Check your email to verify.",
    });
  } else {
    return res.status(400).json({ message: result.message });
  }
});

router.put(
  "/update-password",
  authenticateToken,
  authController.updatePassword
);
router.put(
  "/change-profile-picture",
  authenticateToken,
  upload.single("image"),
  authController.changeProfilePicture
);
router.put(
  "/update-user-details",
  authenticateToken,
  authController.updateUserDetails
);

router.get("/home", authenticateToken, checkSessionExpiration, (req, res) => {
  const user = req.session.user;
  if (!user) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  res.status(200).json({ user });
});

router.get("/forgot-password", (req, res) => {
  res.status(200).json({ message: "Forgot password page" });
});

router.get("/reset-password/:token", (req, res) => {
  const token = req.params.token;
  res.status(200).json({ token });
});

router.get("/verify-email", verifyEmail);

router.get("/resend-verification", authenticateToken, (req, res) => {
  const user = req.session.user;
  if (!user) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const email = user.email;
  res.status(200).json({ email });
});

router.get("/success", (req, res) => {
  res.status(200).json({ message: "Success page" });
});

module.exports = router;
