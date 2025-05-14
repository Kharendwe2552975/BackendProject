// server.js
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const sanitizeHTML = require("sanitize-html");
const session = require("express-session");
const path = require("path");

async function startServer() {
  const db = await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "Kharendwe03!",
    port: 3306,
    database: "backend",
  });

  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS posts (
      id INT AUTO_INCREMENT PRIMARY KEY,
      authorid INT NOT NULL,
      createdDate DATETIME NOT NULL,
      title VARCHAR(100) NOT NULL,
      body TEXT NOT NULL,
      FOREIGN KEY (authorid) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  const app = express();

  app.set("view engine", "ejs");
  app.set("views", path.join(__dirname, "views"));
  app.use(express.urlencoded({ extended: true }));
  app.use(express.static("public"));

  app.use(
    session({
      secret: "yourSecretKey",
      resave: false,
      saveUninitialized: true,
    })
  );

  app.use((req, res, next) => {
    res.locals.errors = [];
    next();
  });

  function isLoggedIn(req, res, next) {
    if (req.session.isLoggedIn) return next();
    res.redirect("/login");
  }

  function sharedPostValidation(req) {
    const errors = [];
    if (typeof req.body.title !== "string") req.body.title = "";
    if (typeof req.body.body !== "string") req.body.body = "";

    req.body.title = sanitizeHTML(req.body.title.trim(), {
      allowedTags: [],
      allowedAttributes: {},
    });
    req.body.body = sanitizeHTML(req.body.body.trim(), {
      allowedTags: [],
      allowedAttributes: {},
    });

    if (!req.body.title) errors.push("Title is required.");
    if (req.body.title.length > 100)
      errors.push("Title cannot exceed 100 characters");
    if (!req.body.body) errors.push("Content is required.");
    if (req.body.body.length > 1000)
      errors.push("Content cannot exceed 1000 characters");
    return errors;
  }

  app.get("/", async (req, res) => {
    if (req.session.isLoggedIn) {
        const [posts] = await db.execute("SELECT * FROM posts WHERE authorid = ?", [req.session.userId]);
        return res.redirect("/dashboard");
    }
        
    res.render("homepage", {
      userId: req.session.userId || null,
      errors: [],
    });
  });

  app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
      if (err) return res.redirect("/dashboard");
      res.clearCookie("connect.sid");
      res.redirect("/");
    });
  });

  
  app.get("/dashboard", isLoggedIn, async (req, res) => {

    try {

      const [posts] = await db.execute(

        "SELECT * FROM posts WHERE authorid = ? ORDER BY createdDate DESC",

        [req.session.userId]

      );

      res.render("dashboard", {

        userId: req.session.userId,

        posts,

      });

    } catch (err) {

      console.error("Error fetching posts:", err);

      res.render("dashboard", {

        userId: req.session.userId,

        posts: [],

        errors: ["An error occurred while fetching posts"],

      });

    }

  });


  app.get("/login", (req, res) => {
    res.render("login", {
      userId: req.session.userId || null,
      errors: [],
    });
  });

  app.post("/login", async (req, res) => {
    const errors = [];

    const { username = "", password = "" } = req.body;

    if (!username.trim() || !password.trim()) {
      errors.push("Invalid username or password");
      return res.render("login", { userId: null, errors });
    }

    try {
      const [rows] = await db.execute(`SELECT * FROM users WHERE username = ?`, [
        username.trim(),
      ]);

      if (!rows.length || !(await bcrypt.compare(password, rows[0].password))) {
        errors.push("Invalid username or password");
        return res.render("login", { userId: null, errors });
      }

      req.session.userId = rows[0].id;
      req.session.username = rows[0].username;
      req.session.isLoggedIn = true;
      req.session.save(() => res.redirect("/dashboard"));
    } catch (err) {
      console.error(err);
      errors.push("An error occurred. Please try again.");
      res.render("login", { userId: null, errors });
    }
  });

  app.post("/register", async (req, res) => {
    const errors = [];

    const username = req.body.username?.trim() || "";
    const password = req.body.password || "";

    if (!username) errors.push("You must provide a username");
    if (username.length < 3 || username.length > 10)
      errors.push("Username must be 3-10 characters");
    if (!/^[a-zA-Z0-9]+$/.test(username))
      errors.push("Username can only contain letters and numbers");
    if (password.length < 8 || password.length > 70)
      errors.push("Password must be 8-70 characters");

    if (errors.length)
      return res.render("homepage", { userId: null, errors });

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const [result] = await db.execute(
        `INSERT INTO users (username, password) VALUES (?, ?)`,
        [username, hashedPassword]
      );
      req.session.userId = result.insertId;
      req.session.username = username;
      req.session.isLoggedIn = true;
      req.session.save(() => res.redirect("/dashboard"));
    } catch (err) {
      if (err.code === "ER_DUP_ENTRY") {
        return res.render("homepage", {
          userId: null,
          errors: ["That username is already taken"],
        });
      }
      throw err;
    }
  });

  app.get("/create-post", isLoggedIn, (req, res) => {
    res.render("create-post", {
      userId: req.session.userId,
      errors: [],
    });
  });

app.get("/edit-post/:id", isLoggedIn, async (req, res) => {
  const postId = req.params.id;

  if (!postId || isNaN(postId)) {
    return res.redirect("/");
  }

  const [rows] = await db.execute(
    `SELECT * FROM posts WHERE id = ? AND authorid = ?`,
    [postId, req.session.userId]
  );

  if (!rows.length) {
    return res.redirect("/");
  }

  res.render("edit-post", {
    userId: req.session.userId,
    post: rows[0],
    errors: [],
  });
});

// Saving the edited post
app.post("/edit-post/:id", isLoggedIn, async (req, res) => {
  const postId = req.params.id;
  const errors = sharedPostValidation(req);

  if (errors.length) {
    return res.render("edit-post", {
      userId: req.session.userId,
      post: { id: postId, ...req.body },
      errors,
    });
  }

  const { title, body } = req.body;

  try {
    const [result] = await db.execute(
      `UPDATE posts SET title = ?, body = ? WHERE id = ? AND authorid = ?`,
      [title, body, postId, req.session.userId]
    );

    if (result.affectedRows === 0) {
      return res.redirect("/");
    }

    res.redirect(`/post/${postId}`);
  } catch (err) {
    console.error("Update Error:", err);
    res.render("edit-post", {
      userId: req.session.userId,
      post: { id: postId, ...req.body },
      errors: ["An error occurred while updating the post"],
    });
  }
});

// Deleting the post
app.post("/delete-post/:id", isLoggedIn, async (req, res) => {
  const postId = req.params.id;

  if (!postId || isNaN(postId)) {
    return res.redirect("/");
  }

  try {
    const [rows] = await db.execute(
      `SELECT authorid FROM posts WHERE id = ?`,
      [postId]
    );

    if (!rows.length) {
      return res.redirect("/dashboard");
    }

    if (rows[0].authorid !== req.session.userId) {
      return res.status(403).render("403", {
        userId: req.session.userId,
        errors: ["You are not authorized to delete this post"],
      });
    }

    await db.execute(`DELETE FROM posts WHERE id = ? AND authorid = ?`, [
      postId,
      req.session.userId,
    ]);
    res.redirect("/dashboard");
  } catch (err) {
    console.error("Delete Error:", err);
    res.redirect("/dashboard");
  }
});

// Middleware to check if the user is the author of a post
app.use((req, res, next) => {
  res.locals.isAuthor = (postAuthorId) => {
    return req.session.userId === postAuthorId;
  };
  next();
});

app.get("/post/:id", async (req, res) => {  
    const postId = req.params.id;
    const [rows] = await db.execute(
      `SELECT posts.*, users.username AS author FROM posts JOIN users ON posts.authorid = users.id WHERE posts.id = ?`,
      [postId]
    );

    if (!rows.length) {
      return res.status(404).render("404", {
        userId: req.session.userId,
        errors: ["Post not found"],
      });
    }

    res.render("post", {
      userId: req.session.userId,
      post: rows[0],
    });
  }
  );

  app.post("/create-post", isLoggedIn, async (req, res) => {
    const errors = sharedPostValidation(req);

    if (errors.length) {
      return res.render("create-post", {
        userId: req.session.userId,
        errors,
      });
    }

    const { title, body } = req.body;
    const userId = req.session.userId;

    try {
      const createdDate = new Date().toISOString().slice(0, 19).replace("T", " ");
      const [result] = await db.execute(
        `INSERT INTO posts (authorid, createdDate, title, body) VALUES (?, ?, ?, ?)`,
        [userId, createdDate, title, body]
      );
      res.redirect(`/post/${result.insertId}`);
    } catch (err) {
      console.error("Insert Error:", err);
      res.render("create-post", {
        userId,
        errors: ["An error occurred while creating the post"],
      });
    }
  });

  app.listen(3000, () => console.log("Server running on http://localhost:3000"));
}

startServer();
