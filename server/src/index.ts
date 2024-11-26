import express from 'express'
import { config } from 'dotenv'
import { createServer } from 'https'
import { readFileSync } from 'fs';
import { createClient } from '@supabase/supabase-js';
import { v4 as uuid } from 'uuid';

config()
const app = express();
const port = process.env.PORT;
const radius = process.env.RADIUS_SERVER_API;
const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_API_KEY!)

type User = {
    profile: any,
    [key: number]: [Date, Date]
};

app.get('/', (req, res) => {
    res.send('Hello, world!');
})

app.get('/reg-company', async (req, res) => {
    /*
        body expects: {
            companyName: string,
            defaultProfile: Json
        } 
    */
    const companyName = req.body.companyName! as string;
    const defaultProfile = req.body.defaultProfile! as any;
    // Register the company with supabase
    const { error } = await supabase.from('companies').insert({
        name: companyName,
        default_profile: defaultProfile,
    })

    if (error)
        res.status(403).send('Could not register company');
    else
        res.status(200).send('Company registered');
})


/*
    {
        companyId: companyId,
        users: [
            { <- this is one user
                profile: json,
                nasid: [start, expiration],
                othernas: [start, otherExpiration]
            }
        ]
    }
*/
app.get('/gen-cert', async (req, res) => {
    const companyId = req.body.companyId! as string;
    const users = req.body.users! as User[];

    type RadiusInfo = {
        commonName: string,
        start: Date,
        end: Date,
    }

    let radiusRequest: RadiusInfo[] = [];
    for (const user of users) {
        // Store all nasnames in string array by bulk querying nasids
        let nasKeys: string[] = []
        let start: Date | null = null;
        let end = new Date(Date.now());
        const profile = user.profile;

        for (const key in user) {
            if (key === 'profile') continue;
            nasKeys.push(key);

            const [userStart, userEnd] = [new Date(user[key][0]), new Date(user[key][1])]
            start = (start && ((start as Date) < userStart)) ? start : userStart;
            end = end > userEnd ? end : userEnd;
        }

        let nasnames: string[] = []

        {
            let { data, error } = await supabase.from('nas').select('nasname').in('nasname', nasKeys);
            if (error || !data) {
                res.status(404).send(`Error: ${error}`);
                return;
            }
            nasnames = data.map(item => item.nasname) as string[];
        }
        
        // Generate a uuid common name
        const commonName = uuid();

        // Push to radiusRequest with commonName and the first date defined as well as the last date defined
        radiusRequest.push({
            commonName,
            start: start ?? new Date(Date.now()),
            end,
        });

        // Insert into the sql table the user using the common name and companyId
        {
            let user = await supabase.from('radcheck').insert({
                username: commonName,
                allowed_nas: nasnames,
                attribute: 'TLS-Cert-Common-Name',
                op: ':=',
                value: 'yuh 🔥'
            }).select()
            if (user.error || !user.data) {
                res.status(404).send(`Error: ${user.error}`);
                return;
            }

            let { data, error } = await supabase.from('users').insert({
                company_id: companyId,
                id: user.data[0].id,
                profile
            }).select()
            if (error || !data) {
                res.status(404).send(`Error: ${error}`);
                return;
            }
        }
    }

    // Call endpoint on radius server to generate the certificate given the common name (and optionally other information)
    // This endpoint should return the p12 file as text in the json body (+ any format required by any device, so parllely create the libressl version as well and for windows encode using the ca.der file and so on)
    // The returned certificate should be pkcs7 signed or smtg
    // Download the returned certificate to client from this endpoint

    res.send('Success');
});

const server = createServer({
    key: readFileSync('src/certs/server-key.pem'),
    cert: readFileSync('src/certs/server-cert.pem'),
}, app);
server.listen(port, () => {
    console.log(`[server]: Server is running at http://localhost:${port}`);
});