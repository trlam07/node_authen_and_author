// authenticate
// authorization
const http = require('http')
const url = require('url')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')

const items = [
    {id: 1, name: 'item 1', description: 'description item 1'},
    {id: 2, name: 'item 2', description: 'description item 2'},
    {id: 3, name: 'item 3', description: 'description item 3'},
]

const users = [
    {email: 'user1@gmail.com', password: 'user 1', role: 'admin'},
    {email: 'user2@gmail.com', password: 'user 2', role: 'user'},
]

const secretKey = '123';
const refreshTokens = [];

const hashPassword = async(password) => {
    const saltRound = 10;
    return await bcrypt.hash(password, saltRound)
}

const comparePassword = async(password, hashedPassword) => {
    return await bcrypt.compare(password, hashedPassword)
}

const generateAccessToken = (email, password, role) => {
    return jwt.sign({email, password, role}, secretKey, {expiresIn: '30m'})
}

const generateRefreshToken = (email) => {
    return jwt.sign({email}, secretKey, {expiresIn: '7d'})
}

const register = (req, res) => {
    let body = '';
    req.on('data', (chunk) => {
        body += chunk.toString()
    })
    req.on('end', async() => {
        const newUser = JSON.parse(body)
        newUser.password = await hashPassword(newUser.password);
        users.push(newUser)
        const cloneNewUser = {...newUser}
        delete cloneNewUser.password;
        res.writeHead(201, {'Content-Type': 'application/json'})
        res.end(JSON.stringify({
            message: 'Register Success',
            data: cloneNewUser
        }))
    })
}

const login = (req, res) => {
    let body = '';
    req.on('data', (chunk) => {
        body += chunk.toString()
    })
    req.on('end', async() => {
        const {email, password, role} = JSON.parse(body)
        const checkEmailUser = users.find(user => user.email === email) 
        if (checkEmailUser) {
            const checkPasswordUser = await comparePassword(password, checkEmailUser.password)
            if (checkPasswordUser) {
                const accessToken = generateAccessToken(email, password, role)
                const refreshToken = generateAccessToken(email)
                refreshTokens.push(refreshToken);
                const cloneUser = {...checkEmailUser};
                delete cloneUser.password;
                res.writeHead(200, {'Content-Type': 'application/json'})
                res.end(JSON.stringify({
                    message: 'Login Success',
                    data: {
                        data: cloneUser,
                        accessToken, 
                        refreshToken,
                        } }))
            } else {
                res.writeHead(401, {'Content-Type': 'text/plain'})
                res.end('Unauthorized')
            }
        } else {
            res.writeHead(401, {'Content-Type': 'text/plain'})
            res.end('Unauthorized')
        }
    })
}

const server = http.createServer((req, res) => {
    const parseUrl = url.parse(req.url, true)
    if (req.method === 'POST' && parseUrl.pathname === '/api/auth/register') {
        register(req, res)
    } else if (req.method === 'POST' && parseUrl.pathname === '/api/auth/login') {
        login(req, res)
    }
    else {
        res.writeHead(404, {'Content-Type': 'text/plain'})
        res.end('Not found')
    }
})

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Server is running at ${PORT}`)
})