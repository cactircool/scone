import { Router } from 'express'
import { supabase } from '../lib'

export const router = Router()

/*

    Use a get request for logging in with email and password,
    Use a put request for logging in with third party services

*/

type ExpectedTypeParam = 'company' | 'third-party'

// Header must contain email and password fields
router.get('/:type/login', async (req, res) => {
    let type: ExpectedTypeParam | undefined = undefined;
    switch (req.params.type) {
        case 'company':
        case 'third-party':
            type = req.params.type;
            break;
        default:
            res.status(422).send(`Login operation must be done on type=(company | third-party), given '${req.params.type}'`)
            return
    }

    const [email, password] = [req.get('email'), res.get('password')]
    if (!email || !password) {
        res.status(422).send(`Malformed request, expected request headers to contain fields 'email' and 'password' populated accordingly`)
        return
    }

    try {
        const [user, result] = await Promise.all([
            supabase.auth.signInWithPassword({
                email: email,
                password: password,
            }),
            supabase.from(type === 'company' ? 'companies' : 'nas').select(`
                *,
                roles(
                    email,
                    role
                )
            `)
            .eq('roles.email', email)
            .eq('roles.role', type)
            .single(),
        ])

        if (user.error || result.error) {
            res.status(500).json(user.error || result.error)
            return
        }

        const { roles, ...rest } = result.data
        res.status(200).json({
            ...roles,
            ...rest,
            id: user.data.user.id
        })
    } catch (e) {
        res.status(500).json(e)
    }
})

// Matches the expected supabase type
type ExpectedTokenCredentials = {
    /** Provider name or OIDC `iss` value identifying which provider should be used to verify the provided token. Supported names: `google`, `apple`, `azure`, `facebook`, `kakao`, `keycloak` (deprecated). */
    provider: 'google' | 'apple' | 'azure' | 'facebook' | 'kakao' | (string & {})
    /** OIDC ID token issued by the specified provider. The `iss` claim in the ID token must match the supplied provider. Some ID tokens contain an `at_hash` which require that you provide an `access_token` value to be accepted properly. If the token contains a `nonce` claim you must supply the nonce used to obtain the ID token. */
    token: string
    /** If the ID token contains an `at_hash` claim, then the hash of this value is compared to the value in the ID token. */
    access_token?: string
    /** If the ID token contains a `nonce` claim, then the hash of this value is compared to the value in the ID token. */
    nonce?: string
    options?: {
        /** Verification token received when the user completes the captcha on the site. */
        captchaToken?: string
    }
}

// Body must conform to the above type under the "creds" key
router.put('/:type/login', async (req, res) => {
    let type: ExpectedTypeParam | undefined = undefined;
    switch (req.params.type) {
        case 'company':
        case 'third-party':
            type = req.params.type;
            break;
        default:
            res.status(422).send(`Login operation must be done on type=(company | third-party), given '${req.params.type}'`)
            return
    }

    const isExpected = (a: any): a is ExpectedTokenCredentials => 'token' in a;
    if (!isExpected(req.body.creds)) {
        res.status(422).send('Invalid request, malformed body')
        return
    }

    try {
        const user = await supabase.auth.signInWithIdToken(req.body.creds);
        const result = await supabase.from(type === 'company' ? 'companies' : 'nas').select(`
            *,
            roles(
                email,
                role
            )
        `)
        .eq('roles.email', user.data.user!.email)
        .eq('roles.role', type)
        .single()

        if (user.error || result.error) {
            res.status(500).json(user.error || result.error)
            return
        }

        const { roles, ...rest } = result.data
        res.status(200).json({
            ...roles,
            ...rest,
            id: user.data.user.id,
        })
    } catch (e) {
        res.status(500).json(e)
    }
})