const express = require('express');
require('dotenv').config();
const mongoose = require('mongoose');
const app = express();
const passport = require('passport');
const session = require('express-session');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const passportLocalMongoose = require('passport-local-mongoose');
const nodemailer = require('nodemailer');
const {sendEmail} = require('./resetPass');
const crypto = require('crypto');

//Different methods to store password.(encryption and md5 hashing)
//const hash = require('md5');
// const encrypt = require('mongoose-encryption');
//const bcrypt = require('bcrypt');

//This is called Middleware which will be called for every requests to server
app.use(session({
    secret: "Our little secret",
    resave: false,
    saveUninitialized: false,
    cookie: {}
}));

//using passport package to initialize and uses session package
app.use(passport.initialize());
app.use(passport.session());

//Enable Body Parser
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

//Set Ejs
app.set("view engine", "ejs");

//Enable public folder
app.use(express.static("public"));

//Creating User Schema
const userSchema = new mongoose.Schema({
    email_id: String,
    password: String,
    secrets: String,
    token: String,
    tokenExpiration: {
        type: Date,
        default: null, // Initialize the token expiration field with null
    }
});

// DbSchema uses the plugin for passport-local-mongoose package
userSchema.plugin(passportLocalMongoose);

//Encrypting password field
//const secret = "secretpasswordencryption";
//userSchema.plugin(encrypt, {secret: secret, encryptedFields: ["password"]});

const users = mongoose.model("Users", userSchema);

//Connect Database
mongoose.connect(process.env.DB_URL)
    .then(() => console.log("Database Connected"))
    .catch((err) => console.log(err));

//Here db-model used to create strtegy and serialize and deserialize 
passport.use(users.createStrategy());

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, {
            id: user.id,
            email_id: user.username || user.email_id,
        });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, done) {
        users.findOne({ email_id: profile.emails[0].value })
            .then((user) => {
                if (user) {
                    return done(null, user);
                }

                const newUser = new users({
                    email_id: profile.emails[0].value
                });

                newUser.save()
                .then((user)=> {
                    return done(null, user);
                })
                .catch((err)=> {
                    return done(err);
                })
            })
            .catch((err) => {
                return done(err);
            })
    }));

//Managing Get Requests.
app.get("/", (req, res) => {
    res.render("home")
})

app.get("/register", (req, res) => {
    res.render("register")
})

app.get("/login", (req, res) => {
    res.render("login")
})

//Managing Post Requests
app.post("/register", (req, res) => {
    users.register({username: req.body.username}, req.body.password)
    .then((user) => {
        passport.authenticate("local")(req, res, () => {
            res.redirect("/secrets");
        })
    })
    .catch((err) => {
        console.log(err);
        res.redirect("/register");
    })
})

app.post("/login", (req, res) => {
    const newUser = new users({
        email_id: req.body.username,
        password: req.body.password
    })

    req.login(newUser, (err) => {
        if (err) {
            console.log(err);
            res.redirect("/login");
        }
        else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            })
        }
    })
})

app.route("/forgotpassword")
.get((req, res)=> {
    res.render("getmail");
})
.post((req, res)=> {
    const email = req.body.username;
    const token = crypto.randomBytes(20).toString('hex');
    users.findOne({username: email})
    .then((foundUser)=> {
        const userID = foundUser._id;
        foundUser.token = token;
        foundUser.tokenExpiration = new Date(Date.now() + 2 * 60 * 1000); //2 mins from current time.
        foundUser.save().then(()=> {
            sendEmail(email, userID, token);
        })
    })
    .catch((err)=> console.log(err));
    res.send("Check Your Mail");
});

app.route("/resetpassword/:userID/:token")
.get((req, res)=> {
    users.findById(req.params.userID)
    .then((foundUser)=> {
        if(foundUser){
            if(!foundUser.token) res.send("Invalid Request")
            else if(foundUser.token === req.params.token && foundUser.tokenExpiration > new Date()) res.render("changePass")
            else res.send("Invalid Request");
        } else res.send("Invalid Request");
    })
})
.post((req, res)=> {
    async function changePassword(){
        const foundUser = await users.findById(req.params.userID)
        if(foundUser.tokenExpiration > new Date()) {
            await foundUser.setPassword(req.body.password);
        } else res.send("Link Expired");
        
        foundUser.token = "";
        foundUser.tokenExpiration = null;
        foundUser.save()
        .then((result)=> {
            res.redirect("/login");
        }).catch(err=>console.log(err))
    }

    changePassword();
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: '/register' }),
    function (req, res) {
        // Successful authentication, redirect secrets page.
        res.redirect('/secrets');
    }
);

app.get('/secrets', (req, res) => {
    if(req.isAuthenticated()) {
        users.find({secrets: {$ne: null}})
        .then((usersWithSecrets)=> {
            res.render("secrets", {usersWithSecrets: usersWithSecrets})
        })
        .catch((err)=> console.log(err))
    } 
    else res.redirect('/login');
})

app.get('/logout', (req, res) => {
    req.logout((err) => {
        console.log(err);
    });
    res.redirect('/');
})

app.get("/submit", (req, res)=> {
    if (req.isAuthenticated()) {
        res.render('submit');
    }
    else {
        res.redirect('/login');
    }
})

app.post("/submit", (req, res)=> {
    console.log(req.user);
    users.findById(req.user.id)
    .then((foundUser)=> {
        foundUser.secrets = req.body.secret
        foundUser.save().then((secretDoc)=> {
            console.log(secretDoc);
            res.redirect("/secrets")
        })
        .catch((err)=> {
            console.log(err);
        })
    })
    .catch((err)=> {
        console.log(err);
    })
})

app.listen(3000, () => console.log("Server started at port 3000"));

//Register User with bcrypt hash
/*const saltRounds = 10;
bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
    const newUser = new users({
        email_id: req.body.username,
        password: hash
        //password: hash(req.body.password) (if using md5 hashing)
    })

    newUser.save()
        .then((response) => {
            console.log(response)
            res.render("secrets")
        })
        .catch((err) => console.log(err))
})*/

//Login User with bcrypt hash
/*users.findOne({ email_id: req.body.username })
    .then((user) => {
        bcrypt.compare(req.body.password, user.password, (err, result) => {
            if (result) res.render('secrets');
            else res.redirect('/');
        })
    })
.catch((err) => console.log(err))*/
