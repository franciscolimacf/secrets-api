//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const googleAuth = require("./googleoauth");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

const ipdb = process.env.IP_DB;

mongoose.connect(`mongodb://${ipdb}:27017/userDB`);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

app.get("/", function (req, res) {
  res.render("home");
});

app.use("/auth/google", googleAuth);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", async function (req, res) {
  try {
    const foundUser = await User.find({ secret: { $ne: null } });

    res.render("secrets", { userWithSecrets: foundUser });
  } catch (err) {
    console.log(err);
  }
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) console.log(err);
  });
  res.redirect("/");
});

app.post("/register", function (req, res) {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});
app.post("/login", async function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) console.log(err);
    else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/submit", async function (req, res) {
  const submitedSecret = req.body.secret;
  console.log(req.user);

  try {
    const foundUser = await User.findById(req.user.id).exec();

    foundUser.secret = submitedSecret;
    foundUser.save();
    res.redirect("/secrets");
  } catch (err) {
    console.log(err);
  }
});

app.listen(3000, function () {
  console.log("App listening to port 3000");
});
