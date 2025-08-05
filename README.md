## HOW TO START THE SERVER

- node app.js

## SETUP INSTRUCTIONS

1. Must have node.js
2. Must have the keys
3. Must install dependencies (run npm init -y npm install express helmet)

## SSL CONFIGURATIONS

1. I created a folder with my certifcates
2. I then created an object that reads the cert files
3. I then created a way for it to read my passphrase

## CACHING STRATEGIES

1. certain routes have a age of 300 (5 minutes)
2. certain routes have an age of 600 (10 minutes)
3. one of my routes has a stale-while-revalidate to help that route feel faster

## LESSONS LEAERNED

1. how to use helmet
2. inputting the certifacte keys
3. how to read cert keys

## PHASE 2

## DEPENDENCIES

1. install argon2, mongoose, body-parser (npm install express argon2 mongoose body-parser)
2. install passport for google SSO (npm install passport passport-google-oauth20 express-session)
3. use env files (npm install dotenv)
4. instal dependencies for JWT's (npm install jsonwebtoken, npm install cookie-parser)
5. install csurf (npm install csurf cookie-parser)

## HOW TO RUN

1. in the url type https://localhost:3000/auth/google to log in
2. visit https://localhost:3000/profile to look at user
3. visit https://localhost:3000/admin to show youre unable to view
4. change role of user in mongodb compass
5. refresh https://localhost:3000/admin to view
6. visit http://localhost:3000/logout to logout

## AUTHENTICATION MECHANISM

you can register through postman /register
login through postman /login or use google sso
JWT is generated for auth
refreshtoken generated for new access
Passwords are hashed using Argon2 before being stored in MongoDB for security

## RBAC

user - access their own profile and basic features
admin - access all user data and admin only routes

### PHASE 3

## DEPENDENCIES

1. install ejs2 (npm install ejs)
2. install validator and html escapor (npm install express-validator escape-html)

## HOW TO RUN

1. in the url type https://localhost:3000/auth/google to log in
2. visit https://localhost:3000/profile to look at user
3. visit https://localhost:3000/admin to show youre unable to view
4. change role of user in mongodb compass
5. refresh https://localhost:3000/admin to view
6. visit http://localhost:3000/logout to logout

## PART C

4 high severity vulnerabilities

## HOW TO CLONE REPOSITORY

- SETUP CMD

1. Go into CMD
2. decide which folder you want to put the repo in
3. so type cd and put in that path… ex:cd C:\webdev\semester 3\programming languages

- COPY GITHUB ADDRESS

1. go on github
2. click on repo
3. click green code button
4. copy url to clipboard (https)

- PASTE THE GITHUB ADDRESS IN THE CMD

1. type in git clone <url of repo>...
2. ex: git clone https://github.com/myronfel11/Establishing-a-Secure-HTTPS-Server.git
