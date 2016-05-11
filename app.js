"use strict";

//______________________________________BEGIN setup
const Sequelize = require("sequelize");
const connection = new Sequelize("jsfsa", "root", "password");
const bcrypt = require("bcryptjs");
const salt = bcrypt.genSaltSync(10);
const express = require('express');
const path = require('path');
const http = require('http');
const bodyParser = require('body-parser');
const app = express();
const session = require('client-sessions');
const expressHbs = require('express-handlebars');
const csrf = require("csurf");


app.engine('hbs', expressHbs({
    extname: 'hbs'
}));
app.set('view engine', 'hbs');

app.use(bodyParser.json());

app.use(bodyParser.urlencoded({

    extended: true
}));

app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    cookieName: 'session',
    secret: "isuhvouisbvi98r9u23o989473u8roijfnvidnvj",
    duration: 30 * 60 * 1000,
    activeDuration: 5 * 60 * 1000,
    httpOnly: true,
    ephemeral: true
    // secure:true 



}));

//_____________________________________END setup


//_____________________________________BEGIN session check middleware
app.use(csrf());


app.use((req, res, next) => {

    if (req.session && req.session.user) {

        User.findOne({
            where: {
                email: req.session.user.email
            }
        }).then((user) => {
            req.user = user;
            delete req.user.password;
            req.session.user = user;
            res.locals.user = user;


            next();

        });
    } else {

        next();
    }

});

function requireLogin(req, res, next) {
    if (!req.user) {

        res.redirect("/login");
    } else {
        next();
    }
}

//____________________________________END session check middleware



//____________________________________BEGIN models


const User = connection.define("user", {
    firstName: {
        type: Sequelize.STRING
    },
    lastName: {
        type: Sequelize.STRING
    },

    email: {
        type: Sequelize.STRING,
        unique: true

    },
    password: {
        type: Sequelize.STRING,
    }
});

connection.sync();

//____________________________________END models








app.get("/", (req, res) => {
    res.render("index");

});




//............REGISTER...............//

app.get("/register", (req, res) => {
    res.render("register", {
        csrfToken: req.csrfToken()
    });

});

app.post("/register", (req, res) => {

    let hash = bcrypt.hashSync(req.body.password, salt);
    User.build({
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        email: req.body.email,
        password: hash

    }).save().then((savedUser) => {
        req.session.user = savedUser;
        res.redirect("/dashboard");

    }).catch((error) => {
        console.log("user was not created successfully: " + error);

        res.redirect("/");
    });


});


//........ END REGISTER..............//




//........... LOGIN..................//


app.get("/login", (req, res) => {
    res.render("login", {
        csrfToken: req.csrfToken()
    });

});

app.post("/login", (req, res) => {

    User.findOne({
        where: {
            email: req.body.email
        },
    }).then((user) => {

        if (!user) { //________________User does not exist
            res.redirect("/login");
        } else if (bcrypt.compareSync(req.body.password, user.password)) {

            req.session.user = user;
            res.redirect("/dashboard");

        } else { //______________________Password is wrong


            res.redirect("/login");

        }

    });
});

app.get("/logout", (req, res) => {
    req.session.reset();
    res.redirect("/")

});



//........END LOGIN..............//


app.get("/dashboard", requireLogin, (req, res) => {
    res.render("dashboard", {
        csrfToken: req.csrfToken()
    });
});





//____________________________________BEGIN helper functions




//____________________________________END helper functions

//____________________________________BEGIN Start server

app.listen("3000", (err) => {

    if (err) {
        console.log("server is not working");
    } else {
        console.log("Server is working on 3000");
    }
});
//____________________________________END Start server