import express from "express";
import bodyParser from "body-parser";   
import { dirname, join } from "path";             
import { fileURLToPath } from "url"; 
import axios from "axios";       
import pg from "pg";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from 'passport-google-oauth2';


const app = express();
const __dirname = dirname(fileURLToPath(import.meta.url));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(join(__dirname, 'public')));
app.use(express.static(join(__dirname, '/public/css')));
app.use(express.static(join(__dirname, '/public/icons')));
app.use(express.static(join(__dirname, '/public/images')));
app.use(express.static(join(__dirname, 'bootstrap')));

//Setting View engine as EJS
app.set('view engine', 'ejs');
app.set('views', join(__dirname, 'views'));
dotenv.config();

app.use(session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: true,
    cookie:{
        maxAge: 1000*60*60*24
    }
}));

app.use(passport.initialize());
app.use(passport.session());


const db = new pg.Client({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT
});

async function connectDB(){
    try{
        await db.connect();
        console.log(`Connected to the DB.`);
    }
    catch(err){
        console.log(`Couldn't connect to the DB. ${err}`);
    }
}

connectDB();


async function getQuery(query, params){
    try{
        const result = await db.query(query, params);
        console.log("Query has successfully been sent.");
        return result;
    }

    catch(err){
        console.log(`Query couldn't have been sent. ${err}`);
    }
}


async function isValid(email_value){
    const JSON_format = await getQuery("SELECT * FROM users WHERE email = ($1)", [email_value]);
    const user_db = JSON_format.rows;
 
    if(user_db.length === 0){
        console.log("This email not taken yet.");
        return true;
    }
    else{
        console.log("This email is already taken.");
        return false;
    }
}


function sendGet(page_path, file){
    try{
        app.get(page_path, (req , res)=>{
            res.render(file);
        });
    }
    
    catch(err){
        res.send(`
            <h1>An error occured. Try again later.</h1>
            <script>
                setTimeout(() => {
                    window.location.href = '/';  
                }, 1500);
            </script>
        `);
    }

};

sendGet("/", `index.ejs`);
sendGet("/login", `login.ejs`);
sendGet("/register", `register.ejs`);
sendGet("/resetpass", `resetpass.ejs`);


let login_date = "";
let date_counter = 0;
let date_arr = [];
app.get("/secrets",(req , res)=>{
    try{
        if(req.isAuthenticated()){
            console.log(req.isAuthenticated());
            res.render(`secrets.ejs`,{
                name: req.user.name
            }); 
            date_counter += 1;
            login_date = new Date();
            date_arr.push(login_date);
            console.log(`The date the user entered: ${login_date}`);
        }
        else{
            console.log(req.isAuthenticated());
            res.redirect(`/login`);
        }
    }

    catch(err){
        res.send(`
            <h1>An error occured. Try again later.</h1>
            <script>
                setTimeout(() => {
                    window.location.href = '/settings/helpsupport';  
                }, 1500);
            </script>
        `);
    }
    
});

app.post("/secrets",(req , res)=>{
    try{
        const button = req.body.button;
    if(button === "logout"){
        req.logout((err)=>{
            if(err){
                console.log(`Error while logging out. ${err}`);
                res.send(`
                    <h1>Error occured while logging out.</h1>
                    <script>
                        setTimeout(function() {
                            window.location.href = "/";
                        }, 1000); 
                    </script>
                `);
            }
            res.redirect("/");
        });
    }
    else if(button === "submit_secret"){
        res.redirect("/submit");
    }
    else if(button === "settings"){
        res.redirect("/settings");
    }
    }

    catch(err){
        res.send(`
            <h1>An error occured. Try again later.</h1>
            <script>
                setTimeout(() => {
                    window.location.href = '/settings/helpsupport';  
                }, 1500);
            </script>
        `);
    }
    
});


let secret_arr = [];
let secret_arr2 = [];
app.get("/submit", async (req , res)=>{
    try{
        if(req.isAuthenticated()){
            const email_user = req.user.email;
            const JSON_format_secrets = await getQuery("SELECT * FROM secrets WHERE email_user = ($1)", [email_user]);
            const JSON_format_credentials = await getQuery("SELECT * FROM users WHERE email = ($1)", [email_user]);
            const user_db = JSON_format_credentials.rows[0].email;
            const secrets_db = JSON_format_secrets.rows;
           
            for(let i=0;i<secrets_db.length;i++){
                secret_arr.push(secrets_db[i].secret);
            }
    
            res.render(`submit.ejs`,{
                secrets: secret_arr
            });
            secret_arr2 = secret_arr;
            secret_arr = [];
        }
        else{
            res.redirect("/login");
        }
    }

    catch(err){
            res.send(`
        <h1>You are not authenticated!!!</h1>
        <script>
            setTimeout(function() {
                window.location.href = "/";
            }, 1500); 
        </script>
    `);
    }
    
});


app.post("/submit", async (req, res) => {
    try{
        const button = req.body.button;
    const input_value = req.body.secret_input;
    const index = req.body.index;
    const email_user = req.user.email;
    console.log("Email entered: " +req.user.email);  

    if (button === "submit-btn") {
        if (input_value !== "" && input_value[0] !== " ") { // ADDS ALL SECRETS THE USER HAS EVER INSERTED
            await getQuery("INSERT INTO secrets (secret, email_user) VALUES ($1, $2);",[input_value, email_user]);
            secret_arr2.push(input_value);
        }
    } 
    
    else if (button === "clear-btn") {  // DELETES ALL SECRETS THE USER HAD
            await getQuery("DELETE FROM secrets WHERE email_user = $1;",[req.user.email]);
            secret_arr2 = [];
            console.log(`Deleted the arr: ${secret_arr2}`);
        
    } 

    else if (button === "delete-btn") { //DELETES SECRETS CLICKING ON X BUTTON 
        if (index !== undefined && index >= 0 && index < secret_arr2.length) {
        const email_user = req.user.email;
        const JSON_format_secrets = await getQuery(`SELECT * FROM secrets WHERE email_user = ($1)`, [email_user]);
        const user_secrets = JSON_format_secrets.rows;
        console.log("USER SECRETS: "+user_secrets);
        
        const deleted_secret = secret_arr2[index];

        console.log(`Email user is ${email_user} and the secret will be deleted is ${deleted_secret}`);

        await getQuery("DELETE FROM secrets WHERE email_user = ($1) and secret = ($2);", [email_user, deleted_secret]);
        secret_arr2.splice(index, 1);
        console.log(`Deleted the arr: ${secret_arr2}`);
    }

    }
    res.redirect("/submit");
    // console.clear();
    }

    catch(err){
        res.send(`
            <h1>You are not authenticated!!!</h1>
            <script>
                setTimeout(function() {
                    window.location.href = "/";
                }, 1500); 
            </script>
        `);
    }
});

app.get("/settings",(req , res)=>{
    try{
        if(req.isAuthenticated()){
            res.render(`settings.ejs`);
        }
        else{
            res.redirect("/login");
        }
    }
    catch(err){
        res.send(`
            <h1>An error occured. Try again later.</h1>
            <script>
                setTimeout(() => {
                    window.location.href = '/settings/helpsupport'; 
                }, 1500);
            </script>
        `);
    }
    
});

app.get("/settings/termspolicies",(req , res)=>{
    try{
      if(req.isAuthenticated()){
        res.render(`termspolicies.ejs`);
    }
    else{
        res.redirect("/login");
    }  
    }

    catch(err){
        res.send(`
            <h1>An error occured. Try again later.</h1>
            <script>
                setTimeout(() => {
                    window.location.href = '/settings/helpsupport';  
                }, 1500);
            </script>
        `);
    }
   
})

app.get("/settings/helpsupport",(req , res)=>{
    try{
     if(req.isAuthenticated()){
        res.render(`helpsup.ejs`);
    }
    else{
        res.redirect("/login");
    }   
    }

    catch(err){
        res.send(`
            <h1>An error occured. Try again later.</h1>
            <script>
                setTimeout(() => {
                    window.location.href = '/settings/helpsupport';  
                }, 1500);
            </script>
        `);
    }
    
});

app.get("/settings/privsec",(req , res)=>{
    try{
        if(req.isAuthenticated()){
        if(date_counter > 1){
            res.render(`privsec.ejs`,{
                login_date: date_arr[(date_arr.length)-2]
            });
        }

        else if(date_counter === 1){
            res.render(`privsec.ejs`,{
                login_date: "First Login"
            });
        }
        
    }
    else{
        res.redirect("/login");
    }
    }

    catch(err){
        res.send(`
            <h1>An error occured. Try again later.</h1>
            <script>
                setTimeout(() => {
                    window.location.href = '/settings/helpsupport'; 
                }, 1500);
            </script>
        `);
    }
    
});

app.get("/settings/personalinfo",(req , res)=>{
    try{
     if(req.isAuthenticated()){
        const birthday = `${req.user.day} ${req.user.month} ${req.user.year}`;
        res.render("personalinfo.ejs",{
            name: req.user.name,
            surname: req.user.surname,
            email: req.user.email,
            password: req.user.password,
            birthday: birthday,
            gender: req.user.gender
        });
    }
    else{
        res.redirect("/login");
    }   
    }
    catch(err){
        res.send(`
            <h1>An error occured. Try again later.</h1>
            <script>
                setTimeout(() => {
                    window.location.href = '/settings/helpsupport';  
                }, 1500);
            </script>
        `);
    }
    
});

app.post("/settings/privsec", async(req , res)=>{
    const button = req.body.button;
    console.log(button);
    if (button === "change_email") {
        try{
            const email = req.body.email;
            const new_email = req.body.newemail;
            const confirm_email = req.body.confirmemail;
    
            //Altering Cascade Attribute of The DB
            try {
                await db.query(`
                    ALTER TABLE secrets
                    DROP CONSTRAINT secrets_email_user_fkey;
    
                    ALTER TABLE secrets
                    ADD CONSTRAINT secrets_email_user_fkey
                    FOREIGN KEY (email_user) REFERENCES users(email)
                    ON UPDATE CASCADE;
                `);
            } catch (err) {
                console.log(`Cascade operation couldn't be accomplished!! ${err}`);
            }
    
            const JSON_format = await getQuery("SELECT * FROM users WHERE email = ($1)", [req.user.email]);
            console.log(JSON_format.rows);
    
            if (req.user.email === email) {
                if (new_email === confirm_email) {
                    if(new_email != req.user.email){
                        const email_db = JSON_format.rows[0].email;
                    console.log(email_db); //user@gmail.com
                    await getQuery("UPDATE secrets SET email_user = ($1) WHERE email_user = ($2)", [new_email, email_db]);
                    await getQuery("UPDATE users SET email = ($1) WHERE email = ($2)", [new_email, email_db]);
                    res.send(`
                        <h1>Your email has successfully been changed.</h1>
                        <script>
                            setTimeout(function() {
                                window.location.href = "/login";
                            }, 1000); 
                        </script>
                    `);
                    //Put logout here!!!!!!!!!!!!!!!!!!!!!!!
                    req.logout((err)=>{
                        if(err){
                            console.log(`Error while logging out. ${err}`);
                            res.send(`
                                <h1>Error occured while logging out.</h1>
                                <script>
                                    setTimeout(function() {
                                        window.location.href = "/";
                                    }, 1000); 
                                </script>
                            `);
                        }
                        // res.redirect("/");
                    });
                    }

                    else{
                        res.send(`
                            <h1>Your new email can't be the same as the old one!!</h1>
                            <script>
                                setTimeout(function() {
                                    window.location.href = "/settings/privsec";
                                }, 1500); 
                            </script>
                        `);
                    }
                } else {
                    res.send(`
                        <h1>Confirm your email correctly!!</h1>
                        <script>
                            setTimeout(function() {
                                window.location.href = "/settings/privsec";
                            }, 1000); 
                        </script>
                    `);
                }
            } else {
                res.send(`
                    <h1>Email is wrong!!</h1>
                    <script>
                        setTimeout(function() {
                            window.location.href = "/settings/privsec";
                        }, 1000); 
                    </script>
                `);
            }

            
        }
        catch(err){
            res.send(`
                <h1>An error occured while changing your email. Try again later.</h1>
                <script>
                    setTimeout(function() {
                        window.location.href = "/";
                    }, 1000); 
                </script>
            `);
            console.log(`Error occured while changing the email. ${err}`);
        }
    }

    else if(button === "change_password"){
        try{
            const current_password = req.body.password;
            const new_password = req.body.newpassword;
            const confirm_password = req.body.confirmpassword;
    
            console.log(`
                Current Password: ${current_password}
                New Password: ${new_password}
                Confirm Password: ${confirm_password}
                `);
    
                const user_email = req.user.email; //User's email here to get queried
    
            const JSON_format = await getQuery("SELECT (password) FROM users WHERE email=($1)",[user_email]);
            const password_db = JSON_format.rows[0].password;
            console.log(`${req.user.email}'s password is ${password_db}`); //User's password here
    
            const isPasswordCorrect = await bcrypt.compare(current_password, password_db);
            console.log("Password is " + isPasswordCorrect);
    
            if(isPasswordCorrect){
                if(new_password === confirm_password){
                    if(new_password != current_password){
                        console.log("Passwords are MATCHED!!");
                try{
                const new_hashed_password = await bcrypt.hash(new_password, saltRounds);
                // console.log(`Your changed password got hashed as ${new_hashed_password} and it is ${new_password}`);
                await getQuery("UPDATE users SET password = ($1) WHERE email = ($2);",[new_hashed_password, user_email]);
                res.send(`
                    <h1>Your password has successfully been changed.</h1>
                    <script>
                        setTimeout(function() {
                            window.location.href = "/login";
                        }, 1000); 
                    </script>
                `);
                
                req.logout((err)=>{
                    if(err){
                        console.log(`Error while logging out. ${err}`);
                        res.send(`
                            <h1>An error occured while logging out.</h1>
                            <script>
                                setTimeout(() => {
                                    window.location.href = '/settings/helpsupport';
                                }, 1500);
                            </script>
                        `);
                        
                    }
                    // res.redirect("/");
                });
                }
                catch(err){
                    console.log(`An error occured while your changed password was being hashed!!. ${err}`);
                }
                    }

                else{
                    res.send(`
                        <h1>Your new password can't be the same as the old one!!</h1>
                        <script>
                            setTimeout(function() {
                                window.location.href = "/settings/privsec";
                            }, 1500); 
                        </script>
                    `);
                }
                 
               
                }
    
                else{
                    res.send(`
                        <h1>Confirm your password correctly!!</h1>
                        <script>
                            setTimeout(() => {
                                window.location.href = '/settings/privsec';
                            }, 1500);
                        </script>
                    `);
                }
    
            }
            else{
                console.log("Passwords are not MACTHED, TRY AGAIN!!!");
                res.send(`
                    <h1>Your password is wrong!!!</h1>
                    <script>
                        setTimeout(() => {
                            window.location.href = '/settings/privsec';
                        }, 1500);
                    </script>
                `);
            }
        }

        catch(err){
            res.send(`
                <h1>An error occured while changing your password. Try again later.</h1>
                <script>
                    setTimeout(() => {
                        window.location.href = '/login';
                    }, 1500);
                </script>
            `);
            console.log(`Error occured while changing the password. ${err}`);
        }
        
    }

    else if(button === "delete_account"){
       try{
        const password = req.body.password;
        const confirm_password = req.body.confirmpassword;

        const JSON_format = await getQuery("SELECT * FROM users WHERE email = ($1)", [req.user.email]);
        const user_password = JSON_format.rows[0].password;
        console.log(`${req.user.email}'s password is ${user_password}`);

        const isPasswordCorrect = await bcrypt.compare(password, user_password);
        console.log("The password the user entered is " + isPasswordCorrect);

        if(isPasswordCorrect){
            if(password === confirm_password){
                try{
                    await getQuery("DELETE FROM secrets WHERE email_user = ($1)", [req.user.email]);
                    await getQuery("DELETE FROM users WHERE email = ($1)", [req.user.email]);
                    console.log(`${req.user.email}'s account has been deleted.`);
                    res.send(`
                        <h1>Your account has successfully been deleted. It was honorable to see you :(</h1>
                        <script>
                            setTimeout(function() {
                                window.location.href = "/";
                            }, 1500); 
                        </script>
                    `);
                    
                    req.logout((err)=>{
                        if(err){
                            console.log(`Error while logging out. ${err}`);
                            res.send(`
                                <h1>Error occured while logging out.</h1>
                                <script>
                                    setTimeout(() => {
                                        window.location.href = '/';
                                    }, 1500);
                                </script>
                            `);
                        }
                        // res.redirect("/");
                    });
                }
                
                catch(err){
                    console.log(`An error occured while deleting the account. ${err}`);
                    res.send(`
                        <h1>An error occured while your account was being deleted.</h1>
                        <script>
                            setTimeout(() => {
                                window.location.href = '/';
                            }, 1500);
                        </script>
                    `);
                }
            }
            
            else{
                res.send(`
                    <h1>Confirm your password to delete the account.</h1>
                    <script>
                        setTimeout(() => {
                            window.location.href = '/settings/privsec';
                        }, 1500);
                    </script>
                `);
            }
            
        }

        else{
            res.send(`
                <h1>Your credentials are wrong!!</h1>
                <script>
                    setTimeout(() => {
                        window.location.href = '/settings/privsec';
                    }, 1500);
                </script>
            `);
        }
       }

       catch(err){
        res.send(`
            <h1>Error occured while deleting your account.</h1>
            <script>
                setTimeout(function() {
                    window.location.href = "/";
                }, 1500); 
            </script>
        `);
        console.log(`Error occured while deleting the account. ${err}`);
       }
    }

});



app.post("/settings/helpsupport", (req, res) => {

    try {
        const name = req.body.name;
        const email = req.body.email;
        const phone = req.body.phone;
        const topic = req.body.topic;
        const message = req.body.message;

        const user_message = {
            name: name,
            email: email,
            phone: phone,
            topic: topic,
            message: message
        };

        console.log(`
            The message came from support page:
            ${JSON.stringify(user_message)}
        `);

        res.send(`
            <h1>Your message has been taken in. Thanks for your attention :)</h1>
            <script>
                setTimeout(() => {
                    window.location.href = '/settings/helpsupport';
                }, 1500);
            </script>
        `);
    } 
    
    catch (err) {
        console.log(`Error occurred while having a message from support page. ${err}`);
        res.send(`
            <h1>Your message hasn't been sent. Forgive us :(</h1>
            <script>
                setTimeout(() => {
                    window.location.href = '/settings/helpsupport';
                }, 1500);
            </script>
        `);
    }
});

app.post("/settings",(req , res)=>{
    try{
       const button = req.body.button;
    if(button === "terms_pol"){
        res.redirect(`/settings/termspolicies`);
    }
    else if(button === "help_sup"){
        res.redirect(`/settings/helpsupport`);
    }
    else if(button === "priv_sec"){
        res.redirect(`/settings/privsec`);
    }
    else if(button === "personal_info"){
        res.redirect("/settings/personalinfo");
    } 
    }
    catch(err){
        res.send(`
            <h1>An error occured. Try again later.</h1>
            <script>
                setTimeout(() => {
                    window.location.href = '/settings/helpsupport'; 
                }, 1500);
            </script>
        `);
    }
    
});


app.get("/auth/google/login", passport.authenticate("google",{
    scope: ["profile", "email"]
}));

app.get("/auth/google/register", passport.authenticate("google",{
    scope: ["profile", "email"]
}));


app.get("/auth/google/secrets",passport.authenticate("google",{
    successRedirect: "/secrets",
    failureRedirect: "/login"
}));

const saltRounds = 10;

app.post("/",(req , res)=>{
    try{
       const button = req.body.button;
    if(button === "register"){
        res.redirect("/register");
    }
    else if(button === "login"){
        res.redirect("/login");
    } 
    }
    catch(err){
        res.send(`
            <h1>An error occured. Try again later.</h1>
            <script>
                setTimeout(() => {
                    window.location.href = '/settings/helpsupport';  
                }, 1500);
            </script>
        `);
    }
    
});


app.post("/register", async (req , res)=>{
    try{
        const name = req.body.name;
        const surname = req.body.surname;
        const email = req.body.email;
        const password = req.body.password;
        const day = req.body.birthday;
        const month = req.body.birthmonth;
        const year = req.body.birthyear;
        const gender = req.body.gender;
    
        let isTaken = await isValid(email);
    
        console.log(`ISTAKEN İS ${isTaken}`);
    
        if(isTaken){
            const hashed_password = await bcrypt.hash(password, saltRounds);
        
    
            console.log(`
                Name: ${name}
                Surname: ${surname}
                Email: ${email}
                Password: ${password}
                Hashed Password: ${hashed_password}
                Birthday: ${day}
                Birthmonth: ${month}
                Birthyear: ${year}
                Gender: ${gender}
                `);
        
                await getQuery("INSERT INTO users (name, surname, email, password, day, month, year, gender) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);", [name, surname, email, hashed_password, day, month, year, gender]);
        
                res.send(`
                    <h1>Successfully Registered :)) WELCOME, ${name} :)</h1>
                    <script>
                        setTimeout(function() {
                            window.location.href = "/";
                        }, 1500); 
                    </script>
                `);
        }
    
        else{
            res.send(`
                <h1>Unfortunately, this email is already taken.</h1>
                <script>
                    setTimeout(function() {
                        window.location.href = "/";
                    }, 1500); 
                </script>
            `);
        }
    }

    catch(err){
        console.log(`An error occured while registering. ${err}`);
        res.send(`
            <h1>An error occurred while registering!!</h1>
            <script>
                setTimeout(function() {
                    window.location.href = "/";
                }, 1500); 
            </script>
        `);
    }
    
 
});


app.post("/login", passport.authenticate("local",{
    successRedirect: "/secrets",
    failureRedirect: "/login"
}));


//Works amazingly good. Don't come back down here.
app.post("/resetpass", async (req , res)=>{
    try{
        const email = req.body.email;
    const password = req.body.currentpass;
    const new_password = req.body.newpassword;
    const confirm_password = req.body.confirmpass;

    const JSON_format = await getQuery(`SELECT * FROM users WHERE email = ($1)`, [email]);
    const user_data = JSON_format.rows;
 
    if(user_data.length > 0){
        const password_db = user_data[0].password;

         //If the password entered is correct, returns true
         let isPasswordCorrect = await bcrypt.compare(password, password_db);

        if(isPasswordCorrect === true){

            if(new_password === confirm_password){
                const new_hashed_password = await bcrypt.hash(new_password, saltRounds);
                await getQuery(`UPDATE users SET password = ($1) WHERE email = ($2);`,[new_hashed_password, email]);
                res.send(`
                    <h1>Your password has successfully been changed :))</h1>
                    <script>
                        setTimeout(() => {
                            window.location.href = '/login';
                        }, 1000);
                    </script>
                `);
            }
            else{
                res.send(`
                    <h1>Confirm your new password correctly!!!</h1>
                    <script>
                        setTimeout(() => {
                            window.location.href = '/resetpass';
                        }, 1000);
                    </script>
                `);
            }
        
           }

        else{
            res.send(`
                <h1>Wrong credentials to change the password !!!</h1>
                <script>
                    setTimeout(() => {
                        window.location.href = '/resetpass';
                    }, 1000);
                </script>
            `);
           }
    }

    else{
        // res.send("<h1>User not found !!!</h1>");
        res.send(`
            <h1>User not found !!!</h1>
            <script>
                setTimeout(() => {
                    window.location.href = '/resetpass';
                }, 1000);
            </script>
        `);
    }
    }
    
    catch(err){
        console.log(`An error occured while resetting the password. ${err}`);
        res.send(`
            <h1>An error occured while resetting your password.</h1>
            <script>
                setTimeout(() => {
                    window.location.href = '/';
                }, 1000);
            </script>
        `);
    }

});


passport.use(new LocalStrategy({usernameField: 'email',passwordField: 'password'}, async (email, password, cb) => {
    console.log("GOT INNN!!");
    const JSON_format = await getQuery(`SELECT * FROM users WHERE email = ($1);`, [email]); 
    const user_data = JSON_format.rows[0];
    console.log(JSON_format.rows);

    try{

        if(JSON_format.rows != ""){
            const password_db = user_data.password;
            await bcrypt.compare(password, password_db, (err, result)=>{
                 if(err){
                     console.log(err);
                     return cb(err);
                 }
                 else if(result){
                     return cb(null, user_data);  //isAuthenticated() is currently activated.
                 }
                 else if(!result){
                     return cb(null, false);
                 }
             });
        }
        else{
            return cb("USER NOT FOUND!!");
        }

    }

    catch(err){
        console.log(err);
    }
   
       
}));

let counter = 0;
passport.use("google",new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
}, async (accessToken, refreshToken, profile, cb)=>{

    console.log(profile);
    try{
        const JSON_format = await getQuery(`SELECT * FROM users WHERE email = ($1)`,[profile.email]);
        const db_result = JSON_format.rows;
        if(db_result.length === 0){
            console.log("User doesn't exist. But i saved it tho.");
                const new_user = await getQuery("INSERT INTO users (name, surname, email, password) VALUES ($1, $2, $3, $4);", [profile.given_name, profile.family_name, profile.email, 'google password']);
                cb(null, new_user.rows[0]);
        }
        else{
            //Already existing user
            console.log("User exists.");
             cb(null, db_result[0]);
        }

    }
    catch(err){
         cb(err);
    }

}));

passport.serializeUser((user_data, cb)=>{
     cb(null, user_data);
});

passport.deserializeUser((user_data, cb)=>{
     cb(null, user_data);
});


const port = 3000;
app.listen(port, () => {
    console.log(`Listening on port ${port}...`);
});