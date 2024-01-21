import express from "express";
import bodyParser from "body-parser";
import session from "express-session";
import crypto from "crypto";
const app = express();

app.set("view engine", "ejs");

//Body-parser för formdata.
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: "my_secret_key",
    resave: false,
    saveUninitialized: true,
    cookie: {
      sameSite: strict, //Cookies inkluderas i requests utanför den egna sidan.
    },
  })
);

// Dummy user data
let userData = {
  username: "kristian@example.com",
  password: "123", // Never store passwords like this in a real app
};

// Enkel auth-middleware
function isAuthenticated(req, res, next) {
  if (req.session.loggedIn) {
    next();
  } else {
    res.redirect("/login");
  }
}

// Middleware som verifierar att det skickas med samma token som genererades för sessionen.
function verifyCsrfToken(req, res, next) {
  if (req.session.csrfToken === req.body._csrf) {
    next();
  } else {
    res.send("Invalid CSRF-token");
  }
}

// Login route
app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === userData.username && password === userData.password) {
    const csrfToken = crypto.randomBytes(64).toString("hex"); //En lång random sträng.
    req.session.csrfToken = csrfToken; // Token knyts till den aktuella sessionen.
    req.session.loggedIn = true;
    res.redirect("/");
  } else {
    res.send("Invalid username or password");
  }
});

// Logout route
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

// Route to display the profile
app.get("/", isAuthenticated, (req, res) => {
  res.render("index", {
    username: userData.username,
    csrfToken: req.session.csrfToken, //CSRF-token skickas med till formuläret.
  });
});

// Route to update the email - Vulnerable to CSRF
app.post("/update-email", isAuthenticated, verifyCsrfToken, (req, res) => {
  userData.username = req.body.username;
  res.redirect("/");
});

app.listen(8000, () => {
  console.log("Server running on localhost:8000");
});
