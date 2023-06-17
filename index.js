import * as net from 'net'
import { readFileSync, writeFileSync, existsSync } from 'fs'
import express from 'express'
import bodyParser from 'body-parser'
import path from 'path'
import { fileURLToPath } from 'url'
import { createInterface } from 'readline'
import { createServer } from 'https'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const key = readFileSync('./key.pem')
const cert = readFileSync('./cert.pem')

let rules = []
let defaultRule = {}
let webAuthSettings = {}
let nat = []
const servers = []
const authenticatedUsers = []
let connectLog = []
let authLog = []
const authAttempts = {}

// Define log file locations.
const log = {
  main: './log/log.txt',
  connections: './log/connections.csv',
  auth: './log/auth.csv'
}

// Handle new incoming connection.
const handleConnection = (orig) => {
  const remoteAddress = ipvConvert(orig.remoteAddress)
  const localAddress = ipvConvert(orig.localAddress)
  logger(`New connection from ${remoteAddress}:${orig.remotePort}`)

  // Store logs about connection for logging.
  const connectionLogs = {
    startTime: new Date().toString(),
    endTime: null,
    remoteAddress,
    remotePort: orig.remotePort,
    localAddress,
    localPort: orig.localPort,
    natDestinationAddress: null,
    natDestinationPort: null,
    error: null,
    authenticated: null,
    allowed: null,
    dataTransferred: 0
  }

  // Firewall rules.
  let allowed = defaultRule.allow ? defaultRule.allow : true // If connection is allowed by rules.
  let authenticated = defaultRule.requireAuth ? !defaultRule.requireAuth : false // If origin IP has been authenticated / does not require auth.
  let host // NAT destination host.
  let port // NAT destination port.

  rules.forEach(rule => {
    // Check if rule remote address matches or if no remote address provided.
    if (!rule.remote || (!rule.remote.host && !rule.remote.range) || (rule.remote.host === remoteAddress)) {
      // Check if rule local address matches or if no local address provided.
      if (!rule.local || !rule.local.host || (rule.local.host === localAddress)) {
        // Check if rule local port matches or if no local port provided.
        if (!rule.local || !rule.local.port || (rule.local.port === orig.localPort)) {
          // Check if connection allowed.
          if (rule.allow !== undefined) allowed = rule.allow
          if (rule.requireAuth !== undefined) authenticated = !rule.requireAuth
        }
      }
    } else if (rule.remote && rule.remote.range) {
      // Check if rule remote IP range matches.
      const range = new net.BlockList()
      range.addRange(rule.remote.range.start, rule.remote.range.end)
      if (range.check(remoteAddress)) {
        // Check if rule local address matches or if no local address provided.
        if (!rule.local || !rule.local.host || (rule.local.host === localAddress)) {
        // Check if rule local port matches or if no local port provided.
          if (!rule.local || !rule.local.port || (rule.local.port === orig.localPort)) {
            // Check if connection allowed.
            if (rule.allow !== undefined) allowed = rule.allow
            if (rule.requireAuth !== undefined) authenticated = !rule.requireAuth
          }
        }
      }
    }
  })

  connectionLogs.allowed = allowed

  // Check if remote IP address has not been authenticated.
  if (!authenticated && !authenticatedUsers.includes(remoteAddress)) {
    logger(`Connection from ${remoteAddress}:${orig.remotePort} to ${localAddress}:${orig.localPort} refused due to no authentication.`)
    orig.destroy()
    // Write logs to log.
    connectionLogs.authenticated = false
    connectionLogs.endTime = new Date().toString()
    connectLog.push(connectionLogs)
    return
  }

  connectionLogs.authenticated = true

  // Pass data from incoming connection to destination,
  const onConnData = (d) => {
    dest.write(d)
  }

  // Connection closed event.
  const onConnClose = () => {
    logger(`Connection from ${remoteAddress}:${orig.remotePort} closed.`)
    connectionLogs.endTime = new Date().toString()
    connectLog.push(connectionLogs)
  }

  // Connection error event.
  const onConnError = (err) => {
    logger(`Error from ${remoteAddress}:${orig.remotePort}: ${err}.`, true)
    connectionLogs.error = err
  }

  orig.on('data', onConnData)
  orig.once('close', onConnClose)
  orig.on('error', onConnError)

  // Check NAT rules for port and address.
  nat.forEach(n => {
    if ((n.from.host === localAddress || !n.from.host) && (n.from.port === orig.localPort)) {
      // Determine NAT destination.
      host = n.to.host
      port = n.to.port
    }
  })

  connectionLogs.natDestinationAddress = host
  connectionLogs.natDestinationPort = port

  // If connection was not allowed.
  if (!allowed) {
    logger(`Connection from ${remoteAddress}:${orig.remotePort} refused.`)
    orig.destroy()
    connectionLogs.endTime = new Date().toString()
    connectLog.push(connectionLogs)
    return
  }

  logger(`Connected ${remoteAddress}:${orig.remotePort} via NAT ${localAddress}:${orig.localPort} => ${host}:${port}.`)

  // Connect to NAT destination.
  const dest = net.connect({
    host,
    port
  })

  // Pass data from NAT destination back to origin.
  dest.on('data', (d) => {
    orig.write(d)
    connectionLogs.dataTransferred += d.byteLength
  })
  dest.on('error', e => logger(`Could not connect ${remoteAddress}:${orig.remotePort} to ${host}:${port}: ${e}`, true))
}

// Load rules from file.
const loadRules = () => {
  const data = JSON.parse(readFileSync('./settings.json'))
  rules = data.rules
  defaultRule = data.defaultRule
  webAuthSettings = data.webAuth
  nat = data.nat
}
loadRules()
setInterval(() => { loadRules() }, 300000)

// Start new NAT server.
const startNatServer = (rule) => {
  return new Promise(resolve => {
    const server = net.createServer()
    servers.push(server)
    server.on('connection', handleConnection)

    server.listen({ port: rule.from.port, host: rule.from.host }, () => {
      logger(`New NAT server: ${rule.from.host}:${rule.from.port} => ${rule.to.host}:${rule.to.port}`)
      resolve()
    })
  })
}

// Check that NAT servers match NAT rules.
// Start missing servers and stop unused servers.
const checkNatServers = async () => {
  servers.forEach((server) => {
    let found = false
    nat.forEach(rule => {
      if (!found && (server.address().address === rule.from.host || !rule.from.host) && server.address().port === rule.from.port) {
        found = true
      }
    })
    if (!found) {
      logger(`Stopping NAT server: ${server.address().address}:${server.address().port}`)
      servers.splice(servers.indexOf(server), 1)
      server.close()
    }
  })

  for (let i = 0; i < nat.length; i++) {
    const rule = nat[i]
    let found = false
    servers.forEach(server => {
      if (server && !found && (server.address().address === rule.from.host || !rule.from.host) && server.address().port === rule.from.port) {
        found = true
      }
    })
    if (!found) {
      await startNatServer(rule)
    }
  }
}

checkNatServers()
setInterval(() => { checkNatServers() }, 3000)

// Starts web server for authentication
const startWebAuthServer = () => {
  // Create server.
  const webAuthServer = express()
  webAuthServer.use(bodyParser.json())
  webAuthServer.use(bodyParser.urlencoded({ extended: true }))
  // Send auth page.
  webAuthServer.get('/', function (req, res) {
    res.sendFile(path.join(__dirname, '/webAuth.html'))
  })

  // Process credentials.
  webAuthServer.post('/auth', function (request, response) {
    const ip = ipvConvert(request.ip)
    logger(`WebAuth attempt for ${request.body.user}.`)

    // Count failed attempts.
    if (!authAttempts[ip]) {
      authAttempts[ip] = { count: 0 }
    }

    // Calculate random cooldown based on failed attempts.
    const multiplier = webAuthSettings.cooldownMultiplier ? webAuthSettings.cooldownMultiplier : 2
    const maxFails = webAuthSettings.maxFailCount ? webAuthSettings.maxFailCount : 3

    const maxCooldown = 3500 // Default max of random cooldown for no failed attempts.
    const minCooldown = authAttempts[ip].count > maxFails ? authAttempts[ip].count * multiplier * 1000 : 1000
    const cooldown = Math.max(minCooldown, Math.random() * maxCooldown)

    setTimeout(() => {
      // If username and password correct.
      if (webAuthSettings.users[request.body.user] && webAuthSettings.users[request.body.user].password === request.body.pass) {
        response.send('Authentication successful.')
        const time = webAuthSettings.users[request.body.user].timeout ? webAuthSettings.users[request.body.user].timeout : 240
        logger(`${request.body.user} authenticated from ${ip} for ${time} seconds.`)
        // Store IP address.
        authenticatedUsers.push(ip)
        authLog.push({
          time: new Date().toString(),
          timeout: time,
          ip: request.ip,
          success: true
        })
        // Auth expiry.
        setTimeout(() => {
          authenticatedUsers.splice(authenticatedUsers.indexOf(request.body.user, 1))
          logger(`${request.body.user} authentication from ${ip} has expired.`)
        }, time * 1000)
      } else {
        // Incorrect username/password
        response.send('Failed to authenticate.')
        logger(`${request.body.user} failed to authenticate from ${ip}.`)
        authLog.push({
          time: new Date().toString(),
          timeout: null,
          ip: request.ip,
          success: false
        })
        authAttempts[ip].count++
      }
    }, cooldown)
  })
  // Serve gradientAnimator.
  webAuthServer.get('/gradientAnimator.js', (req, res) => { res.sendFile(path.join(__dirname, '/gradientAnimator.js')) })
  // Start listening.
  const p = webAuthSettings.port ? webAuthSettings.port : 2265
  if (webAuthSettings.https) {
    createServer({ key, cert }, webAuthServer).listen(p)
    logger(`WebAuth server started in HTTPS mode on port ${p}.`)
  } else {
    webAuthServer.listen(p)
    logger(`WebAuth server started in HTTP mode on port ${p}.`)
  }
}

// Handle commands.
const rl = () => {
  const readline = createInterface({
    input: process.stdin,
    output: process.stdout
  })

  readline.question('', cmd => {
    if (cmd === 'list-users') listAuthUsers()
    else if (cmd === 'write-logs') writeLogs()
    else if (cmd === 'load-rules') {
      console.log('Rules loaded.')
      loadRules()
    }
    readline.close()
    rl()
  })
}
rl()

// Lists authenticated users.
const listAuthUsers = () => {
  console.log('---')
  console.log('Authenticated users:')
  authenticatedUsers.forEach(u => console.log(u))
  console.log('---')
}

// Writes logs to file.
const writeLogs = () => {
  logsExporter(connectLog, log.connections)
  logsExporter(authLog, log.auth)
  connectLog = []
  authLog = []
  console.log('Logs written to file.')
}
setInterval(() => { writeLogs() }, 1800000)

// Exports logs to file.
const logsExporter = (logs, filePath) => {
  if (!logs[0]) return // Check if log is empty.
  let values = ''
  Object.keys(logs[0]).forEach(k => { values += `${k},` })
  let logsFile = existsSync(filePath) ? readFileSync(filePath) : values + '\r\n'
  let csv = ''
  logs.forEach(s => {
    const keys = Object.keys(logs[0])
    keys.forEach(key => {
      csv += `${s[key]},`
    })
    csv += '\r\n'
  })

  logsFile += `${csv}`
  writeFileSync(filePath, logsFile)
}

// Logs messages and prints to console.
const logger = (message, error) => {
  const date = new Date()
  const d = date.toLocaleDateString()
  const t = date.toTimeString().substring(0, 8)
  const logMessage = error ? `<${d} ${t}> !! ${message}` : `[${d} ${t}] >> ${message}`
  console.log(logMessage)
  let logFile = existsSync(log.main) ? readFileSync(log.main) : ''
  logFile += `${logMessage}\r\n`
  writeFileSync(log.main, logFile)
}

// Convert IPv6 addresses to IPv4.
const ipvConvert = (ip) => {
  if (ip.includes('::ffff:')) return ip.substring(7)
  else return ip
}

startWebAuthServer()
