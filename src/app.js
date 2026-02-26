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

app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*",
    credentials: true,
  })
);

app.use(cookie());

// 🔥 Session required for OAuth handshake
app.use(
  session({
    secret: "oauthsecret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use("/api/v1/user", UserRoutes);
app.use("/api/messages", messageRoutes);


module.exports = app;
