// Import the modules this server needs: express for the web server, crypto for hashing passwords, and mysql2 to talk to the database
const express = require("express");
const crypto = require("crypto");
const mysql = require("mysql2");

// Create the express app and allow it to read form data sent in POST requests
const app = express();
app.use(express.urlencoded({ extended: true }));

// Serve the HTML files in the public folder (register.html and login.html)
app.use(express.static("public"));

// Database connection settings. The password comes from an environment variable so it isn't stored in the code
const conn = mysql.createConnection({
  host: "localhost",
  user: "bweyant1",
  password: process.env.DB_PASS,
  database: "watchdb",
  port: 3306
});

// Connect to the database and log whether it worked
conn.connect(function (err) {
  if (err)
    console.log("Couldn't connect to MySQL", err);
  else
    console.log("Database connection established");
});

// Settings used when hashing passwords
const hashRounds = 100000;
const hashLength = 64;

// Turns a plain password and a salt into a hashed password, so the same input always produces the same hash
function hashPassword(plainPass, salt) {
  return crypto.pbkdf2Sync(plainPass, salt, hashRounds, hashLength, "sha512").toString("hex");
}

// Handles the register form: hashes the password with a new random salt and saves the new user in the users table
app.post("/register", function (req, res) {
  // Get the values the user typed into the form
  let username = req.body.username;
  let email = req.body.email;
  let plainPass = req.body.password;

  // Create a random salt and hash the password with it, so the plain password is never stored
  let salt = crypto.randomBytes(16).toString("hex");
  let hashedPass = hashPassword(plainPass, salt);

  // Insert the new user. The ? placeholders keep user input from being run as SQL
  let sql = "insert into users (username, email, password, salt) values (?,?,?,?)";
  conn.query(sql, [username, email, hashedPass, salt], function (err, result) {
    // If the insert fails (for example, the username is already taken), tell the user
    if (err) {
      console.log("There was an error registering the user", err);
      res.send('<p>Registration failed. That username may already be taken.<br><a href="register.html">Try again</a></p>');
    } else {
      // Confirm the registration and link to the login page
      res.send('<p>You have successfully registered. <a href="login.html">Login</a> here</p>');
    }
  });
});

// Handles the login form: finds the user, hashes the typed password with their saved salt, and compares it to the stored hash
app.post("/login", function (req, res) {
  // Get the values the user typed into the form
  let username = req.body.username;
  let plainPass = req.body.password;

  // Look up the user by username
  let sql = "select * from users where username = ?";
  conn.query(sql, [username], function (err, result) {
    if (err) {
      // Something went wrong with the query itself
      console.log("There was an error during login", err);
      res.send("<p>Something went wrong. Please try again.</p>");
    } else if (result.length === 0 || hashPassword(plainPass, result[0].salt) !== result[0].password) {
      // No matching user, or the hashes don't match: login failed, with a link back to the login page
      res.send('<p>The login credentials were incorrect.<br><a href="login.html">Back to login</a></p>');
    } else {
      // The username exists and the password hash matches
      res.send("<p>You have logged in successfully</p>");
    }
  });
});

// Start the server on port 3000
app.listen(3000);