import { Router } from 'express'
import { supabase } from '../lib'
import { PostgrestSingleResponse } from '@supabase/supabase-js'
import { v4 as uuid } from 'uuid'
import { emit } from 'process'

export const router = Router()

interface ExpectedCompanyCreationData {
    companyName: string
    defaultProfile?: any // this is json that we haven't created yet so its anything for now, what's put into this doesn't matter yet anyway
    email: string
    password: string
}

router.put('/company', async (req, res) => {
    const isExpected = (a: any): a is ExpectedCompanyCreationData => 'companyName' in a;
    if (!isExpected(req.body)) {
        res.status(422).send('Invalid request, malformed body')
        return;
    }

    const data: ExpectedCompanyCreationData = req.body

    const response = await supabase.auth.signUp({
        email: data.email,
        password: data.password,
        options: {
            data: {
                name: data.companyName
            }
        }
    })

    if (response.error) {
        res.status(422).json(response.error)
        return
    }


    try {
        const role: PostgrestSingleResponse<any> = await supabase.from('roles').insert({
            id: response.data.user!.id,
            email: data.email,
            role: 'company'
        });

        const company: PostgrestSingleResponse<any> = await supabase.from('companies').insert({
            name: data.companyName,
            default_profile: data.defaultProfile ?? {},
            id: response.data.user!.id
        });

        if (company.error || role.error) {
            res.status(500).json(company.error || role.error)
            return
        }

        res.status(200).json({
            ...company.data,
            ...role.data,
            id: response.data.user!.id
        })
    } catch (e) {
        res.status(500).json(e)
        return
    }
})

interface ExpectedThirdPartyCreationData {
    routerIPAddress: string // Anything works here, even if the ip address string has a netmask baked in as long as it follows a.b.c.d(/e)?
    thirdPartyName: string // This can be like Hilton
    address: string // This will probably be piped back into the geocoding API, so idk how worth it is to represent this by latitude and longitude over the relatively expensive to hold string, this is a later problem though
    type?: string // RADIUS required field, put whatever best describes the location (i.e. hotel, conference center, airport, etc.), defaults to 'other'
    secret: string // sensitive secret
    ports?: number // this data is unused currently and I cannot figure out why its there, for now what you put in shouldn't matter since no query references these columns currently
    server?: string // idek ^
    community?: string // this makes even less sense ^
    description?: string // put whatever you want here
    email: string
    password: string
}

router.put('/third-party', async (req, res) => {
    const isExpected = (a: any): a is ExpectedThirdPartyCreationData => 'routerIPAddress' in a;
    if (!isExpected(req.body)) {
        res.status(422).send('Invalid request, malformed body')
        return
    }

    const data: ExpectedThirdPartyCreationData = req.body
    const response = await supabase.auth.signUp({
        email: data.email,
        password: data.password
    })

    if (response.error) {
        res.status(422).json(response.error)
        return
    }

    let clientError = false;

    try {
        const role: PostgrestSingleResponse<any> = await supabase.from('roles').insert({
            id: response.data.user!.id,
            email: data.email,
            role: 'third_party'
        });

        const nas: PostgrestSingleResponse<any> = await supabase.from('nas').insert({
            shortname: data.thirdPartyName,
            nasname: data.routerIPAddress,
            type: data.type ?? 'other',
            ports: data.ports ?? null,
            secret: data.secret,
            server: data.server ?? null,
            community: data.community ?? null,
            description: data.description ?? null,
            address: data.address.length === 0 ? (() => {
                clientError = true
                throw new Error('Address must be at least 1 character long')
            })() : data.address,
            id: response.data.user!.id,
        });

        if (nas.error || role.error) {
            res.status(500).json(nas.error || role.error)
            return
        }

        res.status(200).json({
            ...nas.data,
            ...role.data,
            id: response.data.user!.id
        })
    } catch (e) {
        if (clientError) {
            res.status(422).json(e)
            return
        }

        res.status(500).json(e)
        return
    }
})

interface UnitExpectedUserCreationData {
    companyId: string, // uuid of the company
    profile: any, // custom user data
    validRanges: { [key: string]: [number, number] }, // Ranges of validity keyed by the third party ip address
}
type ExpectedUserCreationData = UnitExpectedUserCreationData | UnitExpectedUserCreationData[]

const getLaterDate = (a: Date, b: Date) => a > b ? a : b;
const getEarlierDate = (a: Date, b: Date) => a > b ? b : a;

// Pass in a list of units for bulk insertion, or send just one for one by one insertion
router.put('/user', async (req, res) => {
    const isExpected = (a: any): a is ExpectedUserCreationData => true
    if (!isExpected(req.body)) {
        res.status(422).send('Invalid request, malformed request')
        return
    }

    if (!Array.isArray(req.body))
        req.body = [req.body]

    let users: {
        nas: string,
        username: string,
        attribute: string, op: string, value: string,
        profile: any,
        company_id: string,
        valid_from: Date,
        valid_until: Date,
    }[] = []

    let caCalls: [string, number, number][] = []
    for (const user of req.body) {
        const username = uuid()
        let fullRange: [Date, Date] = [new Date(Date.now()), new Date(Date.now())]
        for (const ipAddress in user.validRanges) {
            const range = user.validRanges[ipAddress].map((elem: number) => new Date(elem))
            fullRange[0] = getEarlierDate(fullRange[0], range[0]);
            fullRange[1] = getLaterDate(fullRange[1], range[1]);
            users.push({
                nas: ipAddress,
                username: username,
                attribute: 'Single-Use',
                op: ':=',
                value: 'True',
                profile: user.profile,
                company_id: user.companyId,
                valid_from: range[0],
                valid_until: range[1],
            })
        }

        caCalls.push([ username, Math.round((fullRange[0].getTime() - Date.now()) / 1000), Math.round((fullRange[1].getTime() - fullRange[0]!.getTime()) / 1000) ]);
    }

    const [ca, sql]: [Response, PostgrestSingleResponse<any>] = await Promise.all([
        fetch(process.env.CA_URL!, {
            method: 'PUT',
            body: JSON.stringify(caCalls),
        }),
        supabase.from('radcheck').insert(users)
    ])

    if (sql.error) {
        res.status(500).json(sql.error)
        return
    }

    res.status(200).json({
        users: sql.data,
        certs: (await ca.text()).split(',').slice(0, -1)
    })
})