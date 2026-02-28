const User = require("../models/user.model");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/jwt-token");

const registerUser = async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) {
      throw new Error("All Fields are Required..");
    }
    const existingUserWithEmail = await User.exists({ email: req.body.email });
    if (existingUserWithEmail?._id) {
      throw new Error("User with this email already exists..");
    }
    const existingUserWithFullName = await User.exists({
      fullName: req.body.fullName,
    });
    if (existingUserWithFullName?._id) {
      throw new Error("User with this fullName already exists..");
    }

    const newUser = await User.create({
      fullName,
      email,
      password,
    });

    res.status(201).json({
      success: true,
      message: "User Registered Successfully",
      data: {
        id: newUser._id,
        fullName: newUser.fullName,
        email: newUser.email,
      },
    });
  } catch (error) {
    res.status(400).json({
      error: true,
      message: error.message,
    });
  }
};

const LoginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email) {
      throw new Error("Email is Required");
    }

    const existingUser = await User.findOne({ email });

    if (!existingUser) {
      throw new Error("User does not exist with this email");
    }

    const samePassword = await bcrypt.compare(password, existingUser.password);

    if (!samePassword) {
      throw new Error("Password is incorrect");
    }

    const accessToken = generateAccessToken(existingUser);
    const refreshToken = generateRefreshToken(existingUser._id);

    existingUser.refreshToken = refreshToken;
    await existingUser.save();
    const isProduction = process.env.NODE_ENV === "production";
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "None" : "Lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      success: true,
      message: "User Logged In Successfully",
      accessToken,
      user: {
        id: existingUser._id,
        fullName: existingUser.fullName,
        email: existingUser.email,
      },
    });
  } catch (error) {
    res.status(400).json({
      error: true,
      message: error.message,
    });
  }
};

async function logOutUser(req, res) {
  try {
    const userId = req.user._id;
    await User.findByIdAndUpdate(userId, { refreshToken: null });
    res.clearCookie("refreshToken");
    res.clearCookie("accessToken");
    res.status(200).json({
      success: true,
      message: "User Logged Out Successfully",
    });
  } catch (error) {
    console.error("Error in logOutUser:", error);
    res.status(400).json({
      error: true,
      message: "Internal Server Error",
    });
  }
}

async function getUsers(req, res) {
  try {
    const currentUserId = req.user._id;
    const users = await User.find({ _id: { $ne: currentUserId } }).select(
      "_id fullName email"
    );
    res.status(200).json({ success: true, users });
  } catch (error) {
    res.status(500).json({ error: true, message: error.message });
  }
}

// 🔄 Refresh Access Token
async function refreshAccessToken(req, res) {
  try {
    const token = req.cookies?.refreshToken;

    if (!token) {
      return res.status(401).json({ error: true, message: "No refresh token provided" });
    }

    // Verify the refresh token signature
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    } catch (err) {
      return res.status(401).json({ error: true, message: "Invalid or expired refresh token" });
    }

    // Make sure it matches the token stored in DB (prevents reuse after logout)
    const user = await User.findById(decoded.userId);
    if (!user || user.refreshToken !== token) {
      return res.status(401).json({ error: true, message: "Refresh token revoked" });
    }

    // Issue a fresh access token
    const newAccessToken = generateAccessToken(user);

    return res.status(200).json({
      success: true,
      accessToken: newAccessToken,
    });
  } catch (error) {
    console.error("Error in refreshAccessToken:", error);
    return res.status(500).json({ error: true, message: "Internal Server Error" });
  }
}

module.exports = { registerUser, LoginUser, logOutUser, getUsers, refreshAccessToken };
