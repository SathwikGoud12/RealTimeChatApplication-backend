const express = require("express");
const passport = require("passport");

const {
  registerUser,
  LoginUser,
  logOutUser,
  getUsers,
  refreshAccessToken,
} = require("../controllers/user.controller");

const verifyAccessToken = require("../middlewares/auth.middleware");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/jwt-token");

const router = express.Router();

// 🟢 Normal Auth Routes
router.post("/register", registerUser);
router.post("/login", LoginUser);
router.post("/logout", verifyAccessToken, logOutUser);
router.post("/refresh", refreshAccessToken); // 🔄 Public — no access token needed
router.get("/list", verifyAccessToken, getUsers);

// 🔥 Google OAuth Route - Step 1
router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// 🔥 Google OAuth Route - Step 2 (Callback)
router.get(
  "/google/callback",
  passport.authenticate("google", { session: false }),
  async (req, res) => {
    const user = req.user;

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: false, // change to true in production
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: false,
    });

    res.json({
      success: true,
      message: "Google Login Successful",
      user,
    });
  }
);

module.exports = router;
