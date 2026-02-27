const express = require("express");
const cors = require("cors");
const cookie = require("cookie-parser");
const session = require("express-session");

const passport = require("./config/passport");
const UserRoutes = require("./routes/user.routes.js");
const messageRoutes = require("./routes/message.routes");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.send("API is running 🚀");
});

// ✅ MULTIPLE ORIGIN FIX
const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",")
  : [];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        return callback(null, origin); // ✅ CRITICAL FIX
      } else {
        return callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

app.use(cookie());

app.use(
  session({
    secret: "oauthsecret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// ✅ ROUTES
app.use("/api/v1/user", UserRoutes);
app.use("/api/messages", messageRoutes);

module.exports = app;