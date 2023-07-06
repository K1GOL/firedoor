# :fire: firedoor :door:

Simple firewall and NAT with username and password authentication.

## Installation

Requires Node.js and npm.

```sh
git clone https://github.com/K1GOL/firedoor.git &&\
npm i
```

Run `sudo ./certificateGenerator.sh` (Linux) to generate a self-signed certificate for web authentication HTTPS mode. 

## Usage

```sh
npm start
```

While firedoor is running, use commands

* `list-users` to list authenticated IP addresses.

* `write-logs` to write authentication and connection logs to file immediately.

* `load-rules` to load firewall and NAT rules from file immediately.

Use the web authentication page (default port 2265) to allow traffic from your IP address through the firewall.

Access the admin panel at `<web authentication port>/admin/auth` to remotely view logs.

## Configuration

Configure firedoor in the `settings.json` file. The default `settings.json` includes some example configurations. Documentation of all possible options below.

```js
{
  "webAuth": {
    // Options for the web authentication page.
    // If authentication is not disabled by rules,
    // users will need to log in using
    // this web page for their traffic to be
    // let through the firewall.
    // Authentication is per remote IP address.
    "port": 2265, // Port for the web auth page.
    "https": true, // True for HTTPS, false or leave undefined for HTTP.
    "users": {
      // Define credentials for authentication.
      "username1": {
        // Name of this object is the username.
        "password": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", // Password sha256 hash in hexadecimal.
        "timeout": 120, // Authentication will time out after this many minutes (default 120).
        "admin": true // True if this user can access admin logs.
      },
      "username2": {
        // Name of this object is the username.
        "password": "c0e21a8ff85153deac82fe7f09c0da1b3bd90ac0ae204e78d7148753b4363c03", // Password sha256 hash in hexadecimal.
        "timeout": 240 // Authentication will time out after this many seconds (default 240).
      }
    },
    "maxFailCount": 3, // Authentication attempts will start to be throttled after this many failed attempts. Leave undefined for default (3).
    "cooldownMultiplier": 2 // How much the authentication cooldown will increase. Leave undefined for default (2).
  },
  "nat": [
    // NAT rules, each rule as an object in this array. At least one NAT rule required.
    {
      "from": {
        "host": "192.168.1.106", // From this IP. Leave undefined for 0.0.0.0
        "port": 8080 // From this port.
      },
      "to": {
        "host": "192.168.1.107", // To this IP.
        "port": 80
      }
    },
    {
      "from": {
        "port": 8085 // From this port.
      },
      "to": {
        "host": "127.0.0.1", // To this IP.
        "port": 80
      }
    }
  ],
  "defaultRule": {
    // Default firewall rule that will apply to all connections with no other firewall rules.
    "allow": true, // Allow or deny connection. Leave undefined for default (true).
    "requireAuth": true // If connections are required to be authenticated via web auth page first. Leave undefined for default (false).
  },
  "rules": [
    // Firewall rules, each rule as an object in this array.
    {
      // Match this remote address.
      "remote": {
        "host": "127.0.0.1"
      },
      // Specifying no local address matches all local addresses.
      "allow": true, // If connection is allowed. Leave undefined to use defaultRule.
      "requireAuth": false // If authentication is required. Leave undefined to use defaultRule.
    },
    {
      // Specifying no remote address matches all remote addresses.
      // Matches connections to this local address.
      "local": {
        "host": "192.168.1.106", // Leave undefined for all addresses.
        "port": 9030 // Leave undefined for all ports.
      },
      "allow": true,
      "requireAuth": false
    },
    {
      "remote": {
        // Match this remote IP range.
        "range": {
          "start": "192.168.1.100",
          "end": "192.168.1.255"
        }
      },
      "local": {
        "port": 9000
      },
      "allow": false
    }
  ]
}
```