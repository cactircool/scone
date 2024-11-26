import express from 'express'
import { config } from 'dotenv'
import { createServer } from 'https'
import { readFileSync } from 'fs';
import { createClient } from '@supabase/supabase-js';

config()
const app = express();
const port = process.env.PORT;
const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_API_KEY!)

/*
    Idea:
        Call root
            {
                companyId: companyId,
                users: [
                    { <- this is one user
                        nasid: [start, expiration],
                        othernas: [start, otherExpiration]
                    }
                ]
            }
*/

type User = {
    [key: number]: [Date, Date]
};

app.get('/', (req, res) => {
    res.send('Hello, world!');
})

app.get('/reg-company', (req, res) => {
    /*
        body expects: {
            companyName: string
        } 
    */
    const companyName = req.body.companyName! as string;
    // Register the company with supabase
    res.send('Company registered');
})

app.get('/gen-cert', (req, res) => {
    const companyId = req.body.companyId! as string;
    const users = req.body.users! as User[];

    type RadiusInfo = {
        commonName: string,
        start: Date,
        end: Date,
    }

    let radiusRequest: RadiusInfo[] = [];
    users.forEach(user => {
        // Store all nasnames in string array by bulk querying nasids
        // Generate a uuid common name
        // Push to radiusRequest with commonName and the first date defined as well as the last date defined
        // Insert into the sql table the user using the common name and companyId
        // Create a trigger to delete the user after the last expiration date has expired
    })

    // Call endpoint on radius server to generate the certificate given the common name (and optionally other information)
    // This endpoint should return the p12 file as text in the json body (+ any format required by any device, so parllely create the libressl version as well and for windows encode using the ca.der file and so on)
    // The returned certificate should be pkcs7 signed or smtg
    // Download the returned certificate to client from this endpoint

    res.send('Express + TypeScript Server');
});

const server = createServer({
    key: readFileSync('src/certs/server-key.pem'),
    cert: readFileSync('src/certs/server-cert.pem'),
}, app);
server.listen(port, () => {
    console.log(`[server]: Server is running at http://localhost:${port}`);
});