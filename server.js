const express = require('express');
const app = express();
const path = require('path');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const onclock = process.env.JWT_SECRET

app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');
app.use(express.static(__dirname + '/public'));
app.use(bodyParser.json());

const sqlite3 = require('sqlite3').verbose();

// Create a new database object
const db = new sqlite3.Database('database.sqlite');

// Connect to the database
db.serialize(() => {
  // Create a table
  db.run(
    `
    CREATE TABLE IF NOT EXISTS users (
      userID INTEGER PRIMARY KEY,
      name VARCHAR(50),
      password VARCHAR(255),
      description TEXT,
      pfp_url TEXT
    )
    `,
    (error) => {
      if (error) {
        console.error(error);
      } else {
        console.log('User table created successfully');
      }
    }
  );
});

// Close the database connection
db.close();

app.get("/", function (req, res) {
  let absolutePath = __dirname + '/views/index.html';
  res.sendFile(absolutePath);
});

app.get("/support", function (req, res) {
  let absolutePath = __dirname + '/views/support.html';
  res.sendFile(absolutePath);
});

app.get("/newPost", function (req, res) {
  let absolutePath = __dirname + '/views/post.html';
  res.sendFile(absolutePath);
});

app.get("/canvas", function (req, res) {
  let absolutePath = __dirname + '/views/canvas.html';
  res.sendFile(absolutePath);
});

app.get("/guidelines", function (req, res) {
  let absolutePath = __dirname + '/views/rules.html';
  res.sendFile(absolutePath);
});

app.get("/login", function (req, res) {
  /*let absolutePath = __dirname + '/views/login.html';
  res.sendFile(absolutePath);*/
  res.render('login', { onclock });
});

app.get("/signup", function (req, res) {
  /*let absolutePath = __dirname + '/views/signup.html';
  res.sendFile(absolutePath);*/
  res.render('signup', { onclock });
});

app.get("/u/:username", async (req, res) => {
  const username = req.params.username;
  let data

  try {
    // Connect to the database
    const db = new sqlite3.Database('database.sqlite');

    // Select all columns except password from the users table
    const query = `SELECT userID, name FROM users WHERE name = ?`;
    const rows = await new Promise((resolve, reject) => {
      db.all(query, [username], (error, rows) => {
        if (error) {
          reject(error);
        } else {
          resolve(rows);
          data = rows
        }
      });
    });
    let name = data[0].name
    console.log(name)
    res.render('profile', { name });

    // Close the database connection
    db.close();
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "This user doesn't exist" });
  }
});


app.post("/newU", async (req, res) => {
  console.log("request received");
  const username = req.body.username;
  const password = req.body.password;
  const regex = /\s/;
  const containsSpace = regex.test(username);
  
  // Check if the API key is provided in the request headers
  const providedApiKey = req.body.currentTime;
  if (!providedApiKey || providedApiKey !== onclock) {
    res.status(401).json([{ message: "Unauthorized: API key is missing or invalid" }]);
    return;
  }
  
  if (username.length < 16) {
    if (containsSpace) {
      console.log("String contains a space");
      res.json([{ "message": "NO SPACES" }]);
    } else {
      try {
        // Connect to the database
        const db = new sqlite3.Database('database.sqlite');

        // Check if the username already exists
        const query = `SELECT name FROM users WHERE name = ?`;
        db.get(query, [username], async (err, row) => {
          if (err) {
            console.error("Error:", err);
            res.status(500).json({ message: "Error in new user creation" });
            return;
          }

          if (row) {
            // Username already exists
            console.log("Username already exists:", username);
            res.status(409).json([{ message: "Username already exists" }]);
          } else {
            // Hash the password using bcrypt
            const hashedPassword = await bcrypt.hash(password, 10);

            // Log the query before executing it
            const insertQuery = `INSERT INTO users (name, password) VALUES (?, ?)`;

            // Execute the query
            db.run(insertQuery, [username, hashedPassword], (err) => {
              if (err) {
                console.error("Error:", err);
                res.status(500).json({ message: "Error in new user creation" });
                return;
              }

              console.log("New user created:", username);

              // Close the database connection
              db.close();

              res.json([{ "message": "User creation successful" }]);
            });
          }
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error in new user creation" });
      }
    }
  } else {
    console.log("Name too long");
    res.json([{ "message": "What the heck! Pick a shorter name." }]);
  }
});


app.post("/loginU", async (req, res) => {
  console.log("request received");
  const username = req.body.username;
  const password = req.body.password;
  const regex = /\s/;
  const containsSpace = regex.test(username);
  
  // Check if the API key is provided in the request headers
  const providedApiKey = req.body.currentTime;
  if (!providedApiKey || providedApiKey !== onclock) {
    res.status(401).json([{ message: "Unauthorized: API key is missing or invalid" }]);
    return;
  }

  if (containsSpace) {
    console.log("String contains a space");
    res.json([{ "message": "NO SPACES" }]);
  } else {
    try {
      // Connect to the database
      const db = new sqlite3.Database('database.sqlite');

      // Log the query before executing it
      const query = `SELECT password FROM users WHERE name = ?`;

      // Execute the query with the username as a parameter
      db.get(query, [username], async (err, row) => {
        if (err) {
          console.error("Error:", err);
          res.status(500).json({ message: "Error in user login" });
          return;
        }

        if (row) {
          // User found, compare passwords
          const hashedPassword = row.password;
          const passwordsMatch = await bcrypt.compare(password, hashedPassword);

          if (passwordsMatch) {
            console.log("User logged in:", username);
            res.json([{ "message": "User login successful" }]);
          } else {
            console.log("Incorrect password for user:", username);
            res.status(401).json({ message: "Incorrect username or password" });
          }
        } else {
          console.log("User not found:", username);
          res.status(404).json({ message: "Incorrect username or password" });
        }

        // Close the database connection
        db.close();
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Incorrect username or password" });
    }
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});