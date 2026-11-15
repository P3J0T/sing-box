`http` outbound is a HTTP CONNECT proxy client.

### Structure

```json
{
  "type": "http",
  "tag": "http-out",
  
  "server": "127.0.0.1",
  "server_port": 1080,
  "username": "sekai",
  "password": "admin",
  "path": "",
  "headers": {},
  "tls": {},
  
  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### username

Basic authorization username.

#### password

Basic authorization password.

#### path

Path of HTTP request.

#### send_original_destination

Optional, defaults to `false`. When enabled, send one
`X-Infra-Original-Destination` header on the HTTP CONNECT request to the
configured proxy, containing the original intercepted IPv4 address and port
(`IPv4:443`) from inbound metadata. Missing, invalid, IPv6, non-443, or
non-TCP original destinations fail before proxy dialing. A static `headers`
entry with this name (case-insensitive) is rejected. Destination overrides
change the CONNECT target, not this header. It is not sent inside the tunnel.
Only a central proxy that authenticates the relay independently (for example,
verified mTLS) may use this value for policy; the header itself is not identity.

#### headers

Extra headers of HTTP request.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
