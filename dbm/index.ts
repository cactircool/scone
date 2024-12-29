import express, { json } from 'express'
import cors from 'cors'
import { createServer } from 'https'
import { readFileSync } from 'fs'
import { router as createRouter } from './routes/create'
import { router as authRouter } from './routes/auth'
import { router as deleteRouter } from './routes/delete'
import { router as getRouter } from './routes/get'
import { Agent, setGlobalDispatcher } from 'undici'

const CERT_PREFIX = './certs'
const port = 3000
const app = express()
app.use(cors())
app.use(json())

const agent = new Agent({
    connect: {
        rejectUnauthorized: false
    }
})
setGlobalDispatcher(agent)

app.get('/', (req, res) => {
    res.send('Hello world!');
})

app.use('/create', createRouter)
app.use('/auth', authRouter)
app.use('/delete', deleteRouter)
app.use('/get', getRouter)

const server = createServer({
    key: readFileSync(`${CERT_PREFIX}/server.key`),
    cert: readFileSync(`${CERT_PREFIX}/server.crt`),
    passphrase: process.env.PASSPHRASE,
}, app)

server.listen(port, () => {
    console.log(`Server listening on https://localhost:${port}`)
})