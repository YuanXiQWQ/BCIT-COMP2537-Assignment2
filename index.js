/**
 * Imports
 */
const {MongoClient, ServerApiVersion} = require("mongodb");
const express = require("express");
const port = process.env.PORT || 4000;
const path = require("node:path");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const app = express();
require("dotenv").config();


/**
 * MongoDB Initialisation
 */
const config = {
    user: process.env.MONGODB_USER,
    password: process.env.MONGODB_PASSWORD,
    host: process.env.MONGODB_HOST,
    retryWrites: process.env.MONGODB_RETRY_WRITES,
    writeConcern: process.env.MONGODB_WRITE_CONCERN,
    appName: process.env.MONGODB_APP_NAME
};
const uri = `mongodb+srv://${config.user}:${config.password}@${config.host}/?retryWrites=${config.retryWrites}&w=${config.writeConcern}&appName=${config.appName}`;

// Instantiate MangoDB obj as "client"
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1, strict: true, deprecationErrors: true
    }
});

// Connect (and test)
;(async () => {
    try {
        await client.connect();

        // Test the connection
        await client.db("admin").command({ping: 1});
        console.log("Pinged your deployment. You successfully connected to MongoDB!");

        // List databases
        const databasesList = await client.db().admin().listDatabases();
        databasesList.databases.forEach((db) => console.log(`DB: ${db.name}`));
    } catch (e) {
        console.error(e);
    } finally {
        await client.close();
    }
})().catch(console.dir);
const userCollection = client.db("user").collection("userConfig");

const mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${config.user}:${config.password}@${config.host}/sessions`,
    crypto: {
        secret: process.env.MONGODB_SESSION_SECRET
    }
})

app.use(express.static(__dirname + "/public"));


/**
 * Set middleware and static files
 */
app.use(express.urlencoded({extended: true}));
app.use(express.json());
app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: mongoStore,
    // 1 hour in ms
    cookie: {maxAge: 1000 * 60 * 60},
    saveUninitialized: false,
    resave: false
}));
app.use("/styles", express.static(path.resolve(__dirname, "./public/styles")));

const imgPath = path.resolve(__dirname, "./public/images");

const images = [
    imgPath + "/Nyan.gif",
    imgPath + "/Popopopop.gif",
    imgPath + "/咣当.gif"
]

/**
 * Joi validation
 */
const userSchema = Joi.object({
    username: Joi.string().alphanum().required(),
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

/**
 * Validate user input
 * @param input
 * @throws {Error}
 */
function validateUserInput(input) {
    const {error} = userSchema.validate(input);
    if (error) {
        throw new Error("Invalid user input: " + error.details[0].message);
    }
}

const regexErrorMessage = `
            <h1>400: Invalid Input</h1>
            <pre>
            Checklist for your input:
            Username needs 3–25 characters.
            Email should follow the email format.
            The Password must contain 5–25 characters, including at least 1 letter, 1 number and 1 special character(!@#$%^&*).
            Input should be String.
            Username, email and password should not be empty.
            
            Invalid characters/rules:
            Cannot start with "=" while end with "--".
            Cannot start and end with one or more letter or number(\\w+) while "%$#&" within.
            Cannot have "||".
            Cannot have "and", "or" (single word, which space surrounds).
            Cannot have the following keywords:
            "select", "update", "union", "and", "or", "delete", "insert", "truncate", "char", "into", "substr", "ascii", "declare", "exec", "count", "master", "drop", "execute"
            </pre>
            <form action="/index">
              <input type="submit" value="Back">
            </form>
        `

/**
 * Get requests
 */
app.get("/", (req, res) => {
    res.redirect("/index");
});

app.get("/index", (req, res) => {
    console.log("User accessed");
    let HTML = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Assignment 1</title>
      <link rel="stylesheet" href="/styles/global.css">
    </head>
    <body>
    `
    if (req.session.username) {
        console.log("User logged in, go to member");
        HTML += `
        <h1>Hello, ${req.session.username}!</h1>
        <a href="/member">Go to member area</a>
        <a href="/logout">Logout</a>
        `
    } else {
        console.log("User not logged in, go to index");
        HTML += `
        <a href="/login"> login</a>
        <a href="/signup">register</a>
        `
    }

    HTML += `
    </body>
    </html>
    `
    res.send(HTML);
});

app.get("/login", (req, res) => {
    if (req.session.username) {
        res.redirect("/index")
    } else {
        res.sendFile(path.resolve(__dirname, "./app/html/login.html"));
    }
});

app.get("/signup", (req, res) => {
    if (req.session.username) {
        res.redirect("/index")
    } else {
        res.sendFile(path.resolve(__dirname, "./app/html/signup.html"));
    }
});

app.get("/member", (req, res) => {
    if (req.session.username) {
        res.sendFile(path.resolve(__dirname, "./app/html/member.html"));
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/index");
});

app.get("/random-img", (req, res) => {
    const randomIndex = Math.floor(Math.random() * images.length);
    const imagePath = path.resolve(__dirname, images[randomIndex]);
    console.log(imagePath);
    res.sendFile(imagePath);
});

app.get("/userdata", (req, res) => {
    console.log("get request for userdata");
    res.json({
        username: req.session.username, email: req.session.email
    });
});

app.get("*", (req, res) => {
    res.status(404).send(`
                    <h1>404: Page Not Found</h1>
                    <form action="/index">
                        <input type="submit" value="Back">
                    </form>
                    `);
});

/**
 * Post requests
 */
app.post("/login", (req, res) => {
    const {username, password} = req.body;
    try {
        const email = "nothing@no.com"
        validateUserInput({username, email, password});

        client.connect()
            .then(() => userCollection.findOne({username: username}))
            .then(user => {
                if (user) {
                    return bcrypt.compare(password, user.password)
                        .then(match => {
                            if (match) {
                                req.session.username = username;
                                console.log(
                                    "Spawn new session obj: " + JSON.stringify(req.session));
                                res.redirect("/member");
                                console.log("User logged in");
                            } else {
                                console.log("Wrong password");
                                res.send(`
                                <h1>Wrong Username or Password</h1>
                                <form action="/login">
                                    <input type="submit" value="Try Again">
                                </form>
                                <form action="/signup">
                                    <input type="submit" value="Register">
                                </form>
                            `);
                            }
                        });
                } else {
                    console.log("User does not exist");
                    res.send(`
                    <h1>User not found</h1>
                    <form action="/login">
                        <input type="submit" value="Try Again">
                    </form>
                    <form action="/signup">
                        <input type="submit" value="Register">
                    </form>
                `);
                }
            })
            .catch(e => {
                console.error("Error during login:", e);
                res.status(500).send("Internal server error");
            })
            .finally(() => client.close());
    } catch (e) {
        res.status(400).send(regexErrorMessage);
    }
});


app.post("/signup", (req, res) => {
    try {
        createUser(req.body.username, req.body.email, req.body.password);
        req.session.username = req.body.username;
        console.log("Spawn new session obj: " + JSON.stringify(req.session));
        res.redirect("/member");
    } catch (e) {
        res.status(400).send(regexErrorMessage);
    }
});

/**
 * Function to create a new user in MongoDB.
 * @param username The username.
 * @param email    The user email.
 * @param password The user password.
 * @throws {Error} If user input is invalid.
 */
function createUser(username, email, password) {
    validateUserInput({username, email, password});

    client.connect()
        .then(() => bcrypt.hash(password, 10)
            .then((hashedPassword) => userCollection
                .insertOne({username: username, email: email, password: hashedPassword})))
        .then(() => console.log("User created"))
        .catch(e => console.error(e))
        .finally(() => client.close());
}

app.listen(port, () => console.log(`Server started on port ${port}`));
