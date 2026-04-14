const express = require('express');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcrypt');
const SQLiteStore = require("connect-sqlite3")(session);
const fs = require("fs");
require('dotenv').config();

const app = express();

//Read env and insert
const PORT = process.env.PORT || 8080;
const SESSION_SECRET = process.env.SESSION_SECRET;
const PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const sessionFolder = path.join(__dirname, "sessions");

fs.mkdirSync(sessionFolder, { recursive: true });

//makes it work if there is cloudflare problems since it is a proxy
app.set('trust proxy', 1);

//Parse from data (idk man)
app.use(express.urlencoded({ extended: false }));
app.use('/css', express.static(path.join(__dirname, 'public', 'css')));

//session definitions:
app.use(
    session({
        store: new SQLiteStore({
            db: "sessions.sqlite",
            dir: sessionFolder,
            concurrentDB: true
        }),
        name: "kaspar.sid",
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: "auto",
            maxAge: 60 * 60 * 1000
        }
    })
);


//used to check if you are admin or not
function requireAdmin(req, res, next) {
    if(req.session && req.session.isAdmin) {
        return next();
    }
        else return res.redirect('/login.html');
}

//gets the login page if you are not admin. Sends you towards the index page route if you are admin.
app.get(['/', '/login.html'], (req, res) => {
    if(req.session && req.session.isAdmin){
        return res.redirect('/ManagerPage');
    }
    else return res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

//async for await the comparing of passwords. Checks the password written if its correct with the hash
app.post('/login', async (req, res) => {
    const password = req.body.password;

    const matchPasswords = await bcrypt.compare(password, PASSWORD_HASH);


    if(!matchPasswords){
        return res.redirect('/login.html');
        console.log(`Incorrect password`);
    }

    req.session.regenerate(() => {
        req.session.isAdmin = true;

        console.log(`Password correct login accepted`);

        req.session.save(() => {
            return res.redirect('/ManagerPage')
        });
    });
});

//return with the index page but only runs logic and returns page if requireadmin passes.
app.get('/ManagerPage', requireAdmin, (req, res) => {
    return res.sendFile(path.join(__dirname, 'private', 'index.html'));
});

//logout meaning delete the cookie that says you are admin
app.post('/logout', (req, res) => {
    req.session.destroy(() => {
    res.clearCookie('kaspar.sid');
    return res.redirect('/login.html');
});
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
})