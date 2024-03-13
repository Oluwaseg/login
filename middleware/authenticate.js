const jwt = require("jsonwebtoken");
const User = require("../model/user");

const authenticateToken = (req, res, next) => {
  const token = req.cookies.jwt;

  if (!token) {
    return res.redirect("/api/login");
  }

  jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
    if (err) {
      return res.redirect("/api/login");
    }

    try {
      const user = await User.findById(decodedToken.userId);

      if (!user) {
        return res.redirect("/api/login");
      }

      req.session.user = user;
      next();
    } catch (error) {
      console.error("Error verifying token:", error);
      return next(error);
    }
  });
};

const checkSessionExpiration = (req, res, next) => {
  if (!req.session || !req.session.user) {
    return res.redirect("/api/login");
  }

  next();
};
const verifyEmail = async (req, res) => {
  try {
    const token = req.query.token;

    if (!token) {
      return res
        .status(400)
        .render("error", { status: 400, message: "Invalid token" });
    }

    const user = await User.findOne({ verificationToken: token });

    if (!user) {
      return res
        .status(404)
        .render("error", { status: 404, message: "User not found" });
    }

    user.verificationToken = null;
    user.isVerified = true;
    await user.save();

    res.render("verify-success");
  } catch (error) {
    res.status(500).render("error", { status: 500, message: error.message });
    console.error("Verification failed:", error);
  }
};

module.exports = {
  authenticateToken,
  checkSessionExpiration,
  verifyEmail,
};
