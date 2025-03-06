import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session from "express-session";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import flash from "connect-flash";

const app = express();
const port = 3000;
const saltRounds = 10;

// Session setup
app.use(
  session({
    secret: "secret_word_here",
    resave: false,
    saveUninitialized: true,
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(flash());

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/oauthDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: String,
  googleId: String,
});

const User = mongoose.model("User", userSchema);

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: "give_ur_id_here",
      clientSecret: "secret_here",
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
  new LocalStrategy({ usernameField: "username" }, async function (username, password, done) {
    try {
      const user = await User.findOne({ email: username });

      if (!user) {
        return done(null, false, { message: "User not found. Please register first." });
      }

      bcrypt.compare(password, user.password, (err, valid) => {
        if (err) return done(err);
        if (!valid) return done(null, false, { message: "Incorrect password." });

        return done(null, user);
      });
    } catch (err) {
      return done(err);
    }
  })
);

// Serialize and Deserialize user
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Routes
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs", { errorMessage: req.flash("error") });
});

app.get("/register", (req, res) => {
  res.render("register.ejs", { errorMessage: req.flash("error") });
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
app.post(
  "/login",
  (req, res, next) => {
    passport.authenticate("local", (err, user, info) => {
      if (err) return next(err);
      if (!user) {
        req.flash("error", info.message);
        return res.redirect("/login");
      }
      req.login(user, (err) => {
        if (err) return next(err);
        return res.redirect("/secrets");
      });
    })(req, res, next);
  }
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      req.flash("error", "Email already registered. Please log in.");
      return res.redirect("/login");
    }

    bcrypt.hash(password, saltRounds, async (err, hash) => {
      if (err) {
        console.error("Error hashing password:", err);
        return res.redirect("/register");
      }

      const newUser = new User({ email, password: hash });
      await newUser.save();

      res.send("error", "Registration successful! Please log in.");
      res.redirect("/login");
    });
  } catch (err) {
    console.error(err);
    res.send("error", "An error occurred. Please try again.");
    res.redirect("/register");
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

