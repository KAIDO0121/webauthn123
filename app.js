const express = require("express");
const app = express();
const fido = require('./fido.js');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const enforce = require('express-sslify');
const crypto = require('crypto');

if (process.env.ENFORCE_SSL_AZURE === "true") {
    app.use(enforce.HTTPS({ trustAzureHeader: true }));
}
app.use(express.static('public'));
app.use(cookieParser());
app.use(bodyParser.json());

app.get('/adminCredential', async (req, res) => {
    try {
        const credentials = await fido.getUserAndCredential(req.cookies.credentialId);
        // TODO 
        // if the credential is not admin, return error
        res.json({
            result: credentials
        });
    } catch (e) {
        res.json({
            error: e.message
        })
    }; 
})

app.get('/getAllUserCreds', async (req, res) => {
    try {
        if (!req.cookies.adminReq) {
            throw new Error("Current user is not a admin user, authorized failed");
        }
        const credentials = await fido.getAllUserCreds(req.cookies.credentialId);
        res.json({
            result: credentials
        });
    } catch (e) {
        res.json({
            error: e.message
        })
    }; 
});

app.get('/credential', async (req, res) => {
    try {
        const credentials = await fido.getUserAndCredential(req.cookies.credentialId);
        res.json({
            result: credentials
        });
    } catch (e) {
        res.json({
            error: e.message
        })
    }; 
});

app.put('/credentials', async (req, res) => {
    try {
        const credential = await fido.makeCredential(req.cookies.randomUUID, req.body, req.cookies.adminReq);
        res.json({
            result: {
                id: credential.id
            }
        });
    } catch (e) {
        res.json({
            error: e.message
        });
    }
});

app.delete('/credentials', async (req, res) => {
    try {
        const uid = getUser(req);
        await fido.deleteCredential(uid, req.body.id);
        res.json({});
    } catch (e) {
        res.json({
            error: e.message
        });
    }

});

app.get('/challenge', async (req, res) => {
    try {
        const randomUUID = crypto.randomUUID()
        const challenge = await fido.getChallenge(randomUUID);
        res.json({
            result: challenge,
            randomUUID,
        });
    } catch (e) {
        res.json({
            error: e.message
        });
    };
});

app.put('/assertion', async (req, res) => {
    try {
        const credential = await fido.verifyAssertion(req.cookies.randomUUID, req.body, req.cookies.adminReq);
        res.json({
            result: credential
        });
    } catch (e) {
        res.json({
            error: e.message
        });
    }
});

function getUser(req) {
    if (req.cookies.uid) {
        return req.cookies.uid;
    } else {
        throw new Error("You need to sign out and sign back in again.");
    }
}

app.listen(process.env.PORT || 3000, () => console.log('App launched.'));
