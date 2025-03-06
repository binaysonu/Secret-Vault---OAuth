import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session from "express-session";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

const app = express();
const port = 3000;
const saltRounds = 10;

// Session setup
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
});

const User = mongoose.model("User", userSchema);

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: "YOUR_GOOGLE_CLIENT_ID",
      clientSecret: "YOUR_GOOGLE_CLIENT_SECRET",
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    async function (accessToken, refreshToken, profile, done) {
      try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
          user = new User({ googleId: profile.id, email: profile.emails[0].value });
          await user.save();
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// Local Strategy for Email/Password Authentication
passport.use(
  new LocalStrategy(async function verify(username, password, cb) {
    try {
      const user = await User.findOne({ email: username });
      if (user) {
        bcrypt.compare(password, user.password, (err, valid) => {
          if (err) return cb(err);
          return cb(null, valid ? user : false);
        });
      } else {
        return cb(null, false);
      }
    } catch (err) {
      return cb(err);
    }
  })
);

// Serialize and Deserialize user
passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const user = await User.findById(id);
    cb(null, user);
  } catch (err) {
    cb(err);
  }
});

// Routes
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) return next(err);
    res.redirect("/");
  });
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

// Google OAuth Routes
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// Local Authentication Routes
app.post("/login", passport.authenticate("local", { successRedirect: "/secrets", failureRedirect: "/login" }));

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) console.error("Error hashing password:", err);
        else {
          const newUser = new User({ email, password: hash });
          await newUser.save();
          req.login(newUser, (err) => {
            if (err) console.error(err);
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
