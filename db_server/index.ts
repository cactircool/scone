import express, { json } from 'express'
import cors from 'cors'
import { createServer } from 'https'
import { readFileSync } from 'fs'
import { router as createRouter } from './routes/create'
import { router as authRouter } from './routes/auth'

const CERT_PREFIX = './certs'
const port = 3000
const app = express()
app.use(cors())
app.use(json())

app.get('/', (req, res) => {
    res.send('Hello world!');
})

app.use('/create', createRouter)
app.use('/auth', authRouter)

const server = createServer({
    key: readFileSync(`${CERT_PREFIX}/server.key`),
    cert: readFileSync(`${CERT_PREFIX}/server.crt`)
}, app)

server.listen(port, () => {
    console.log(`Server listening on https://localhost:${port}`)
})