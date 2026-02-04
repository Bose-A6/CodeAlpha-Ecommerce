const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const { body, validationResult } = require("express-validator");

const app = express();
const dbDir = path.join(__dirname, "db");
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
const db = new sqlite3.Database(path.join(dbDir, "ecommerce.db"));

app.use(helmet());
app.use(compression());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use(limiter);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change_this_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
    },
  }),
);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Initialize DB and seed minimal data
db.serialize(() => {
  db.run(
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)",
  );
  db.run(
    "CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price INTEGER, description TEXT)",
  );
  db.run(
    "CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, user_id INTEGER, total INTEGER)",
  );

  db.get("SELECT COUNT(*) as c FROM products", (err, row) => {
    if (!err && row && row.c === 0) {
      const stmt = db.prepare(
        "INSERT INTO products(name,price,description) VALUES(?,?,?)",
      );
      stmt.run("Sample T-Shirt", 499, "Comfortable cotton tee");
      stmt.run("Coffee Mug", 199, "Ceramic mug, 350ml");
      stmt.finalize();
    }
  });
});

// Helpers
function ensureAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  res.redirect("/login");
}

// Routes
app.get("/", (req, res) => {
  db.all("SELECT * FROM products", (err, rows) => {
    if (err) return res.status(500).send("Server error");
    res.render("index", { products: rows, user: req.session.user });
  });
});

app.get("/product/:id", (req, res) => {
  db.get("SELECT * FROM products WHERE id=?", [req.params.id], (err, row) => {
    if (err) return res.status(500).send("Server error");
    if (!row) return res.status(404).send("Product not found");
    res.render("product", { product: row, user: req.session.user });
  });
});

app.get("/register", (req, res) => res.render("register", { errors: null }));
app.post(
  "/register",
  body("username")
    .trim()
    .isLength({ min: 3 })
    .withMessage("Username must be at least 3 chars")
    .escape(),
  body("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 chars"),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.render("register", { errors: errors.array() });

    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) return res.status(500).send("Server error");
      db.run(
        "INSERT INTO users(username,password) VALUES(?,?)",
        [username, hash],
        function (dbErr) {
          if (dbErr)
            return res.render("register", {
              errors: [{ msg: "Username already taken" }],
            });
          res.redirect("/login");
        },
      );
    });
  },
);

app.get("/login", (req, res) => res.render("login", { error: null }));
app.post(
  "/login",
  body("username").trim().escape(),
  body("password").exists(),
  (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username=?", [username], (err, user) => {
      if (err) return res.status(500).send("Server error");
      if (!user) return res.render("login", { error: "Invalid credentials" });
      bcrypt.compare(password, user.password, (cmpErr, same) => {
        if (cmpErr) return res.status(500).send("Server error");
        if (!same) return res.render("login", { error: "Invalid credentials" });
        // small user object in session
        req.session.user = { id: user.id, username: user.username };
        res.redirect("/");
      });
    });
  },
);

app.post("/order", ensureAuth, (req, res) => {
  const total = parseInt(req.body.total, 10) || 0;
  db.run(
    "INSERT INTO orders(user_id,total) VALUES(?,?)",
    [req.session.user.id, total],
    function (err) {
      if (err) return res.status(500).send("Server error");
      res.send("Order placed successfully");
    },
  );
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
