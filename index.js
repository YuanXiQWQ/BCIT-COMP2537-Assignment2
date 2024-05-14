/**
 * Imports
 */
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const express = require("express");
const path = require("node:path");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const app = express();
require("dotenv").config();
const port = process.env.PORT || 10000;

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

// Instantiate MongoDB obj as "client"
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true
    }
});

// Connect (and test)
;(async () => {
    try {
        await client.connect();

        // Test the connection
        await client.db("admin").command({ ping: 1 });
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
});

app.use(express.static(__dirname + "/public"));
app.set('view engine', 'ejs');
app.listen(port, () => console.log(`Server started on http://localhost:${port}`));

/**
 * Set middleware and static files
 */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: mongoStore,
    // 1 hour in ms
    cookie: { maxAge: 1000 * 60 * 60 },
    saveUninitialized: false,
    resave: false
}));
app.use("/styles", express.static(path.resolve(__dirname, "./public/styles")));

/**
 * Joi validation
 */
const userSchema = Joi.object({
    username: Joi.string().alphanum().min(3).max(25).required(),
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

/**
 * Validate user input
 * @param input
 * @throws {Error}
 */
function validateUserInput(input) {
    const { error } = userSchema.validate(input);
    if (error) {
        throw new Error("Invalid user input: " + error.details[0].message);
    }
}

/**
 * Function to check if the user is an admin.
 *
 * @param req The request object.
 * @param res The response object.
 * @param next The next function.
 */
function isAdmin(req, res, next) {
    console.log("Checking if user is admin:", req.session.userType);
    if (!req.session.username) {
        res.redirect("/login");
    } else if (req.session.userType === "admin") {
        next();
    } else {
        res.status(403).render("400", {
            message: "Access denied. You must be an administrator."
        });
    }
}

/**
 * Checks if the id is a valid ObjectId.
 * @param id The id to check.
 * @return {boolean} True if the id is a valid ObjectId, false otherwise.
 */
function isValidObjectId(id) {
    return ObjectId.isValid(id) && (new ObjectId(id)).toString() === id;
}

/**
 * Get requests
 */
app.get("/", (req, res) => {
    res.redirect("/index");
});

app.get("/index", (req, res) => {
    res.render("index", { username: req.session.username, userType: req.session.userType });
});

app.get("/login", (req, res) => {
    if (req.session.username) res.redirect("/index");
    else res.render("login");
});

app.get("/signup", (req, res) => {
    if (req.session.username) res.redirect("/index");
    else res.render("signup");
});

app.get("/member", (req, res) => {
    if (req.session.username) {
        const images = [
            "/images/Nyan.gif",
            "/images/Popopopop.gif",
            "/images/咣当.gif"
        ];
        res.render("member", {
            username: req.session.username,
            userType: req.session.userType,
            images: images
        });
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/index");
});

app.get("/userdata", (req, res) => {
    console.log("get request for userdata");
    res.json({
        username: req.session.username,
        email: req.session.email
    });
});

app.get("/admin", isAdmin, (req, res) => {
    client.connect()
        .then(() => userCollection.find({}).toArray())
        .then(users => {
            res.render("admin", {
                users: users,
                username: req.session.username,
                userType: req.session.userType
            });
        })
        .catch(error => {
            console.error("Failed to fetch users:", error);
            res.status(500).send("Server error");
        })
        .finally(() => client.close());
});

app.get("/admin/promote/:userId", isAdmin, async (req, res) => {
    const userId = req.params.userId;
    if (!isValidObjectId(userId)) {
        return res.status(400).send("Invalid user ID");
    }

    try {
        await client.connect();
        const result = await userCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: { userType: "admin" } }
        );
        if (result.matchedCount === 0) {
            res.status(404).send("User not found");
        } else {
            res.redirect("/admin");
        }
    } catch (error) {
        console.error("Failed to promote user:", error);
        res.status(500).send("Failed to promote user due to server error");
    } finally {
        await client.close();
    }
});

app.get("/admin/demote/:userId", isAdmin, async (req, res) => {
    const userId = req.params.userId;
    if (!isValidObjectId(userId)) {
        return res.status(400).send("Invalid user ID");
    }

    try {
        await client.connect();
        const result = await userCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: { userType: "user" } }
        );
        if (result.matchedCount === 0) {
            res.status(404).send("User not found");
        } else {
            res.redirect("/admin");
        }
    } catch (error) {
        console.error("Failed to demote user:", error);
        res.status(500).send("Failed to demote user due to server error");
    } finally {
        await client.close();
    }
});

app.get("/admin/delete-user/:userId", isAdmin, async (req, res) => {
    const userId = req.params.userId;
    if (!isValidObjectId(userId)) {
        return res.status(400).send("Invalid user ID");
    }

    try {
        await client.connect();
        const result = await userCollection.deleteOne({ _id: new ObjectId(userId) });
        if (result.deletedCount === 0) {
            res.status(404).send("User not found");
        } else {
            res.redirect("/admin");
        }
    } catch (error) {
        console.error("Failed to delete user:", error);
        res.status(500).send("Failed to delete user due to server error");
    } finally {
        await client.close();
    }
});

app.get("*", (req, res) => {
    res.status(404).render("404");
});

/**
 * Post requests
 */
app.post("/login", (req, res) => {
    const { username, password } = req.body;
    try {
        validateUserInput({ username, email: "temp@example.com", password });

        client.connect()
            .then(() => userCollection.findOne({ username: username }))
            .then(user => {
                if (user) {
                    return bcrypt.compare(password, user.password)
                        .then(match => {
                            if (match) {
                                req.session.username = user.username;
                                req.session.userType = user.userType;
                                console.log("User logged in, session:", req.session);
                                res.redirect("/member");
                            } else {
                                console.log("Wrong password");
                                res.send("Wrong Username or Password");
                            }
                        });
                } else {
                    console.log("User does not exist");
                    res.send("User not found");
                }
            })
            .catch(e => {
                console.error("Error during login:", e);
                res.status(500).send("Internal server error");
            })
            .finally(() => client.close());
    } catch (e) {
        res.status(400).render("400", {
            message: "Invalid input data. Please check your input and try again."
        });
    }
});

app.post("/signup", (req, res) => {
    try {
        createUser(req.body.username, req.body.email, req.body.password)
            .then(() => {
                req.session.username = req.body.username;
                res.redirect("/member");
            })
            .catch(error => {
                console.error("Failed to create user:", error);
                res.status(500).send("Failed to create user: " + error.message);
            });
    } catch (e) {
        res.status(400).render("400", {
            message: "Invalid input data. Please check your input and try again."
        });
    }
});

app.post("/admin/edit-user/:userId", isAdmin, async (req, res) => {
    const { username, email, password } = req.body;
    const userId = req.params.userId;

    if (!isValidObjectId(userId)) {
        return res.status(400).send("Invalid user ID");
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await client.connect();
        const result = await userCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: { username, email, password: hashedPassword } }
        );
        if (result.matchedCount === 0) {
            res.status(404).send("User not found");
        } else {
            res.redirect("/admin");
        }
    } catch (error) {
        console.error("Failed to edit user:", error);
        res.status(500).send("Failed to edit user due to server error");
    } finally {
        await client.close();
    }
});

app.post("/admin/create-user", isAdmin, (req, res) => {
    const { username, email, password } = req.body;
    createUser(username, email, password)
        .then(() => res.redirect("/admin"))
        .catch(error => res.status(500).send("Failed to create user: " + error.message));
});

app.post("/admin/edit-user/:userId", isAdmin, (req, res) => {
    const { username, email, password } = req.body;
    const userId = req.params.userId;
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            res.status(500).send("Error hashing password");
        } else {
            client.connect()
                .then(() => userCollection.updateOne({ _id: new MongoClient.ObjectId(userId) },
                    { $set: { username, email, password: hashedPassword } }))
                .then(() => res.redirect("/admin"))
                .catch(error => res.status(500).send("Failed to edit user: " + error.message))
                .finally(() => client.close());
        }
    });
});

/**
 * Function to create a new user in MongoDB.
 * @param username The username.
 * @param email    The user email.
 * @param password The user password.
 * @throws {Error} If user input is invalid.
 */
function createUser(username, email, password) {
    return new Promise((resolve, reject) => {
        validateUserInput({ username, email, password });
        client.connect()
            .then(() => bcrypt.hash(password, 10))
            .then((hashedPassword) => userCollection.insertOne({
                username: username,
                email: email,
                password: hashedPassword,
                userType: "user"
            }))
            .then(result => resolve(result))
            .catch(e => reject(e))
            .finally(() => client.close());
    });
}
