const express = require('express');
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server')
//const crypto = require('node:crypto');

const {Crypto} = require('node-webcrypto-ossl');
const crypto = new Crypto();
global.crypto = crypto;

const PORT = 3000;
const app = express();

app.use(express.static('./public'));

app.use(express.json());

//In memory store for users and challenges. This can vbe replaced by persistent store using mongodb or postgres or any other db
const userstore = {};
const challengeStore = {};

/*
Register a user
 */
app.post('/register', (req, res) => {

    console.log("User is trying to register", req.body);
    const {username, password} = req.body;
    const id = `user_${Date.now()}`;

    const user = {
        id,
        username,
        password
    };
    userstore[id] = user;
    console.log("Registered user", userstore);
    res.json({id});

    // console.log(req.body);
    //  res.send('POST request to the homepage')
});

/*
Register a challenge  - passkey challenge
* */
app.post('/register/challenge', async (req, res) => {
    console.log("User is trying to register challenge...", req.body);
    const {userId} = req.body;
    if (!userstore[userId]) {
        return res.status(404).json({error: 'User not found'});
    }

    const challengePayload = await generateRegistrationOptions({
        rpID: 'localhost',
        rpName: 'My local SimpleWebAuthn Example',
        userId: new TextEncoder().encode(userId),
        userName: userstore[userId].username
    });
    challengeStore[userId] = challengePayload.challenge;
    res.json({options: challengePayload});


    // console.log(req.body);
    //  res.send('POST request to the homepage')
});

/*
Verify the registration response
 */
app.post('/register/verify', async (req, res) => {
    console.log("User is trying to register verify...", req.body);
    const {userId, credential} = req.body;
    if (!userstore[userId]) {
        return res.status(404).json({error: 'User not found'});
    }

    const challenge = challengeStore[userId];
    if (!challenge) {
        return res.status(404).json({error: 'Challenge not found'});
    }

    const result = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',

    });

    if (result.verified) {
        userstore[userId].credential = credential;
        userstore[userId].passkey = result.registrationInfo.passkey;
        res.json({verified: true});
    } else {
        res.status(400).json({error: 'Failed to verify credential'});
    }
});

/*
Login a user using stored challenge
 */
app.post('/login/challenge', async (req, res) => {
    console.log("User is trying to login challenge...", req.body);
    const {userId} = req.body;
    if (!userstore[userId]) {
        return res.status(404).json({error: 'User not found'});
    }

    const loginPayload = await generateAuthenticationOptions({
        rpID: 'localhost'
    });
    challengeStore[userId] = loginPayload.challenge;
    res.json({options: loginPayload});
});


/*
Verify the login response
 */
app.post('/login-verify', async (req, res) => {
       console.log("User is trying to login verify...", req.body);
        const {userId, credential} = req.body;
        const user = userstore[userId];
        if (!userstore[userId]) {
            return res.status(404).json({error: 'User not found'});
        }

        const challenge = challengeStore[userId];
        if (!challenge) {
            return res.status(404).json({error: 'Challenge not found'});
        }

        const result = await verifyAuthenticationResponse({
            response: credential,
            expectedChallenge: challenge,
            expectedOrigin: 'http://localhost:3000',
            expectedRPID: 'localhost',
            authenticator: user.passkey
        });

        if (result.verified) {
            res.json({verified: true, user: user.username});
        } else {
            res.status(400).json({error: 'Failed to verify credential'});
        }
})


app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
