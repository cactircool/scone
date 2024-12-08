import { Router } from 'express'
import { supabase } from '../lib'
import { PostgrestSingleResponse } from '@supabase/supabase-js'

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
        res.status(422).send(`Error creating user: ${response.error.name} (${response.error.status ?? '?'} = ${response.error.code ?? '?'}) ${response.error.message}\n${response.error.stack}`)
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
            res.status(500).send(`Unable to create user for some reason: ${JSON.stringify(company.error || role.error, null, 4)}`)
            return
        }

        res.sendStatus(200).json({
            ...company.data,
            ...role.data,
        })
    } catch (e) {
        res.sendStatus(500).send(`Internal server error: ${JSON.stringify(e, null, 4)}`)
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
        res.status(422).send(`Error creating user: ${response.error.name} (${response.error.status ?? '?'} = ${response.error.code ?? '?'}) ${response.error.message}\n${response.error.stack}`)
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
            res.status(500).send(`Unable to create user for some reason: ${JSON.stringify(nas.error || role.error, null, 4)}`)
            return
        }

        res.sendStatus(200).json({
            ...nas.data,
            ...role.data,
        })
    } catch (e) {
        if (clientError) {
            res.status(422).send(`Client error: ${JSON.stringify(e, null, 4)}`)
            return
        }

        res.sendStatus(500).send(`Internal server error: ${JSON.stringify(e, null, 4)}`)
        return
    }
})