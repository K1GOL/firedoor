# :fire: firedoor :door:

Simple firewall and NAT with username and password authentication.

## Installation

Requires Node.js and npm.

```sh
npm i
```

Run `certificateGenerator.sh` (Linux) to generate a self-signed certificate for web authentication HTTPS mode. 

## Usage

```sh
node index.js
```

While firedoor is running, use commands

* `list-users` to list authenticated IP addresses.

* `write-logs` to write authentication and connection logs to file immediately.

* `load-rules` to load firewall and NAT rules from file immediately.

Use the web authentication page (default port 2265) to allow traffic from your IP address through the firewall.

## Configuration

Configure firedoor in the `settings.json` file.

```json
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
        // Key of this object is the username.
        "password": "password1", // Password
        "timeout": 120 // Authentication will time out after this many seconds (default 240).
      },
      "username2": {
        // Key of this object is the username.
        "password": "password2", // Password
        "timeout": 240 // Authentication will time out after this many seconds (default 240).
      }
    },
    "maxFailCount": 3, // Authentication attempts will start to be throttled after this many failed attempts. Leave undefined for default (3).
    "cooldownMultiplier": 2 // How much the authentication cooldown will increase. Leave undefined for default (2).
  },
  "nat": [
    // NAT rules, each rule as an object in this array.
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