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

1. install argon2, mongoose, body-parser (npm install express argon2 mongoose body-parser)
2. install passport for google SSO (npm install passport passport-google-oauth20 express-session)
3. use env files (npm install dotenv)
4. instal dependencies for JWT's (npm install jsonwebtoken, npm install cookie-parser)
5. install csurf (npm install csurf cookie-parser)
