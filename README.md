# metaice

ICE servers for WebRTC: STUN and TURN servers and STUN protocol tools
for Node.js 22 and later, with no runtime dependencies. The package exports
`IceServer`, `iceServers`, `credentials`, `isPrivate`, `start`,
`protocols`, and the codec as `stun`.
Requiring the package and constructing a server open no sockets or timers.

## Install

```sh
npm install metaice
```

## STUN and TURN server

```js
'use strict';

const { IceServer } = require('metaice');

const main = async () => {
  const server = new IceServer({
    port: 3478,
    secret: process.env.TURN_SECRET ?? '',
  });
  await server.listen();
  console.log(server.ports);
  process.once('SIGINT', async () => {
    await server.close();
  });
};

main().catch(console.error);
```

`listen()` opens UDP4 on `listen`, UDP6 on `::` with `ipv6Only`, and TCP
on `listen`. The listeners share one port. With `port: 0`, UDP4 selects
the port and UDP6 and TCP bind that same port. If the selected port is
already in use, `listen()` closes the partial set and tries another port,
up to ten attempts. When `tlsPort` is nonzero, `listen()` also opens TLS
on `listen` and that port. `server.ports` reports `{ udp, tcp, tls }`.
`tls` is the bound TLS port, or zero when TLS is off. Both address families
must bind successfully. A final bind failure rejects `listen()` after
closing the listeners, connections and relays it opened, and logs a
warning through `console`. One server instance owns every socket and timer.

Binding responses carry the client's XOR-MAPPED-ADDRESS, SOFTWARE, and
FINGERPRINT. Unknown required attributes receive a `420` response with a
distinct UNKNOWN-ATTRIBUTES list. Unknown optional attributes are ignored;
malformed packets are dropped.

TCP and TLS are streams. Each connection is buffered and cut into frames
in order: a STUN message is 20 bytes plus its length, and ChannelData is
4 bytes plus its length, padded up to a multiple of 4. Padding is not
payload. The server writes each response before it reads the next frame
on that connection. UDP stays one datagram per message and does not pad
ChannelData. Outbound ChannelData on TCP and TLS is zero-padded; three
payload bytes occupy an 8-byte frame, and five occupy a 12-byte frame.
Closing the TCP or TLS connection deletes its allocation. TLS reads PEM
files from `tls.key` and `tls.cert`, relative to the working directory,
and uses the same framing as TCP.

An empty `secret` disables TURN while keeping STUN available. With a
secret, UDP, TCP, and TLS clients can Allocate and Refresh relays,
CreatePermission, ChannelBind, send Send indications and ChannelData, and
receive Data indications or ChannelData. Refresh with a zero lifetime
deletes the allocation. Byte-identical retransmissions receive the cached
response for 40 seconds, including while the relay is still opening. A
transaction ID reused with different request bytes is dropped. The cache
holds at most 8192 authenticated transactions.

| Option               | Default              | Meaning                                                                                     |
| -------------------- | -------------------- | ------------------------------------------------------------------------------------------- |
| `listen`             | `'0.0.0.0'`          | UDP4, TCP, and TLS listener address                                                         |
| `port`               | `3478`               | Shared UDP and TCP port; zero selects it                                                    |
| `publicAddress`      | `''`                 | Numeric address advertised for relays; empty selects a public interface, then a private one |
| `relayPorts`         | `[49160, 49359]`     | Inclusive UDP relay port range                                                              |
| `realm`              | `'metaice'`          | Long-term authentication realm                                                              |
| `secret`             | `''`                 | Shared TURN REST secret; empty disables TURN                                                |
| `software`           | `'metaice'`          | SOFTWARE response attribute                                                                 |
| `credentialTtl`      | `86400`              | Credential lifetime in seconds                                                              |
| `allocationsPerPeer` | `10`                 | Simultaneous allocations per credential peer                                                |
| `allocationLifetime` | `[600, 3600]`        | Default/minimum and maximum allocation lifetime in seconds                                  |
| `permissionLifetime` | `300`                | Peer IP permission lifetime in seconds                                                      |
| `channelLifetime`    | `600`                | Channel binding lifetime in seconds                                                         |
| `relayBitrate`       | `5000000`            | Shared sending/receiving token bucket in bits per second per allocation                     |
| `allowPrivatePeers`  | `false`              | Permit private and special peer addresses                                                   |
| `console`            | `globalThis.console` | Logger with log, info, warn, debug, error                                                   |
| `tlsPort`            | `0`                  | TURN over TLS; zero disables it                                                             |
| `tls`                | `null`               | `{ key, cert }` PEM paths relative to the working directory; required with `tlsPort`        |

`host` and `external` from application options are ignored.

`close()` closes every listener, accepted TCP connection, relay socket and
timer, and resolves after all close, including pending opens and relays
already being removed. Repeated calls share the same promise. Use a new
server instance after closing. `stats()` returns
`{ allocations, sent, received, dropped }`, summed over current
allocations. Traffic counts are payload bytes; `dropped` counts rate
limit and relay send failures. Allocation create/delete logs include the
peer, client/relay transports, byte counts and duration.

Open `port` for UDP and TCP and `relayPorts` for UDP in the firewall.
When TLS is enabled, also open `tlsPort` for TCP. Set `publicAddress`
when advertising an address outside the host, such as behind NAT. Keep
the secret outside source control and share it only
with the application issuing credentials. Nonces expire after ten minutes
and are bound to the client address. Authenticated replies carry
MESSAGE-INTEGRITY and FINGERPRINT. Attributes after MESSAGE-INTEGRITY
cannot change server state. Credentials, secrets and packet contents are
never logged.

By default, relays refuse loopback, private, carrier-grade NAT, link-local,
unspecified, multicast, reserved IPv4 and mapped IPv6 peers. Permissions
apply to peer IPs, and permission requests are atomic. Channels bind a
peer IP and port. Expired permissions and channels stop forwarding even
before the sweep timer runs. Each allocation has a one-second token
bucket shared by both traffic directions. Enable `allowPrivatePeers`
only when those peers should be reachable through your TURN server.
`isPrivate(address)` exports the same policy: it returns `true` for a
loopback, private, link-local, multicast, reserved, mapped or non-IP string
and `false` for a public address.

## CLI

`metaice [config]` runs one server in the foreground.

| Argument | Options                                                                                   |
| -------- | ----------------------------------------------------------------------------------------- |
| none     | `IceServer` defaults                                                                      |
| `*.json` | Object from `JSON.parse`                                                                  |
| `*.js`   | CommonJS module that exports the options object and may read `process.env` for the secret |

Any other argument, a missing file, or a value that is not a plain object
prints the error and exits 1. After `listen()`, the process logs the bound
`{ udp, tcp, tls }` ports. `SIGINT` and `SIGTERM` call `close()` once and
exit 0 when delivered to the process. On Windows, use Ctrl+C to send
`SIGINT` from the terminal. Node's `kill('SIGTERM')` force-terminates
Windows processes. A second signal does not start another close. If
`close()` fails, the process prints the error and exits 1. A failed
`listen()` prints the error and exits 1.

```sh
metaice config/ice.js
```

## Running under impress

impress owns the listening ports. A server group lists `stun.turn`.
impress reads `metarhia.protocols` from this package without running it,
then calls `start(options, context)` on each thread of that group.
`protocols` is `['stun.turn', 'stun.nat-discovery']`.

```js
'use strict';

const { start } = require('metaice');

const context = {
  console,
  mode: 'server',
  protocols: ['stun.turn'],
  thread: { group: 'ice', index: 0, count: 1 },
};
const handler = await start(options, context);
handler.connection(socket, info);
handler.datagram(buffer, remote, socket);
await handler.stop();
```

`context.thread` selects this handler. `start` does not bind, and the
return value is `{ connection, datagram, stop }`. `connection` reads a TCP
stream whose TLS is already terminated (`info.tls` selects `tls` or
`tcp`) and resumes the socket after its listeners are attached. `info` is
`{ port, transport, tls, servername, alpn, remote }`. `datagram` dispatches
one UDP packet and replies with `socket.send`. `stop()` closes accepted
connections, relay sockets, and timers, then resolves. A second `stop()`
is safe.

Without `stun.turn` in `context.protocols`, the handler answers Binding
and does not allocate. Each thread receives a contiguous slice of
`relayPorts` (default `[49160, 49359]`, 200 ports). Two threads receive
`[49160, 49259]` and `[49260, 49359]`. The first threads receive one extra
port when the count does not divide the range. A count above the number of
ports throws. The sweep timer runs while TURN is on.

Without `context.thread`, `start` keeps the CLI behavior: it calls
`listen()`, logs `server.ports`, and returns `{ stop }`.

## Browser ICE server list and credentials

```js
'use strict';

const { credentials, iceServers } = require('metaice');

const options = {
  name: 'turn.example.com',
  secret: process.env.TURN_SECRET ?? '',
  peer: 'peer-ada',
};
const servers = iceServers(options);
const identity = credentials(options);
```

`credentials({ secret, peer, credentialTtl, now })` returns
`{ username, credential, expiry }`. The username is `expiry:peer`, the
credential is base64 HMAC-SHA1 of that username, and `expiry` is Unix
seconds. `credentialTtl` defaults to 86400 seconds; `now` defaults to
`Date.now()` in milliseconds. Issue credentials in a trusted application
and pass only the returned username and credential to the browser.

`iceServers({ name, port, tlsPort, secret, peer, credentialTtl, now })`
always returns a STUN entry. With both `secret` and `peer` it adds TURN
UDP and TCP URLs and credentials. A nonzero `tlsPort` also adds a `turns:`
TCP URL. `port` defaults to 3478 and `tlsPort` to zero. Use a DNS name,
IPv4 address, or bracketed IPv6 address as `name`. The application chooses
the name and appends any external ICE entries. Only advertise transports
supported by the server you deploy.

## STUN codec

Create a Binding request with a 12-byte transaction ID and a fingerprint:

```js
'use strict';

const crypto = require('node:crypto');

const { stun } = require('metaice');

const transactionId = crypto.randomBytes(12);
const type = stun.typeOf(stun.METHODS.binding, 'request');
const packet = stun.encode({
  type,
  transactionId,
  attributes: [],
  fingerprint: true,
});
const message = stun.decode(packet);

if (message) {
  console.log(message.kind, message.method);
  console.log(stun.verifyFingerprint(packet, message));
}
```

`decode(buffer)` returns `null` for non-STUN or malformed packets. A
decoded message has `type`, `method`, `kind`, `length`, `transactionId`,
and `attributes`. `kind` is `request`, `indication`, `success`, or `error`;
`length` is the body length from the header. Attributes stay in wire order
as `{ type, value, offset }` records, including duplicates and unknown
types. `offset` is the attribute header's position in the packet.
Transaction IDs and attribute values are views into the input buffer.

`encode(options)` takes `type`, `transactionId`, and an array of
`{ type, value }` attributes. Values are buffers; the encoder adds zero
padding to a multiple of four bytes. Decoding also accepts nonzero
padding. Set `key` to a string or buffer to append MESSAGE-INTEGRITY,
and `fingerprint: true` to append FINGERPRINT after it. Both are optional.

Long-term authentication derives the HMAC key from a username, realm, and
password:

```js
const key = stun.longTermKey('ada', 'metaice', 'secret');
const packet = stun.encode({
  type: stun.typeOf(stun.METHODS.allocate, 'request'),
  transactionId: crypto.randomBytes(12),
  attributes: [],
  key,
  fingerprint: true,
});
const message = stun.decode(packet);

if (message) console.log(stun.verifyIntegrity(packet, message, key));
```

| API                                                       | Result                                                   |
| --------------------------------------------------------- | -------------------------------------------------------- |
| `METHODS`, `ATTRIBUTES`, `CLASSES`                        | Protocol method, attribute, and message class constants  |
| `typeOf(method, kind)`, `methodOf(type)`, `classOf(type)` | Message type conversions                                 |
| `isStun(buffer)`                                          | Checks minimum header size, top bits, and magic cookie   |
| `decode(buffer)`, `encode(options)`                       | Decoded message or `null`, encoded buffer                |
| `find(message, type)`                                     | First matching attribute or `undefined`                  |
| `attribute(type, value)`                                  | Encoded attribute with header and padding                |
| `header(type, length, transactionId)`                     | Encoded 20-byte STUN header                              |
| `hmac(key, data)`, `crc(data)`                            | HMAC-SHA1 or four-byte STUN fingerprint                  |
| `verifyIntegrity(buffer, message, key)`                   | Checks MESSAGE-INTEGRITY                                 |
| `verifyFingerprint(buffer, message)`                      | Checks the final FINGERPRINT attribute                   |
| `longTermKey(username, realm, password)`                  | MD5 long-term credential key                             |
| `readAddress(value, transactionId)`                       | Decoded XOR address with `family`, `address`, and `port` |
| `writeAddress(address, transactionId)`                    | Encoded IPv4 or IPv6 XOR address                         |
| `parseV4(address)`, `parseV6(address)`, `formatV6(bytes)` | Address byte conversions; IPv6 output uses eight groups  |
| `errorCode(code, reason)`                                 | Encoded ERROR-CODE attribute value                       |

`COOKIE`, `HEADER_SIZE`, `FINGERPRINT_XOR`, `INTEGRITY_SIZE`, and
`FINGERPRINT_SIZE` are also exported on `stun`. TypeScript declarations
describe the codec and its message, attribute, address, and options types.

## Development

```sh
npm install
npm test
```

| Command                           | Checks                                                         |
| --------------------------------- | -------------------------------------------------------------- |
| `npm run lint`                    | ESLint and Prettier                                            |
| `npm run fix`                     | Applies ESLint fixes and Prettier formatting                   |
| `npm run types`                   | TypeScript declarations                                        |
| `npm test`                        | Lint, declarations, and Node tests                             |
| `node --test test/stun.js`        | Codec tests only                                               |
| `node --test test/binding.js`     | UDP4, UDP6, TCP, and lifecycle tests                           |
| `node --test test/credentials.js` | REST credentials, nonces and ICE URLs                          |
| `node --test test/turn.js`        | TURN security, replay, lifetime and rate tests without sockets |
| `node --test test/turn-udp.js`    | Real UDP TURN protocol, relay and shutdown tests               |
| `node --test test/turn-tcp.js`    | TCP framing, padding, close, and TLS TURN                      |
| `node --test test/service.js`     | Service start, stop, and a require that does not listen        |
| `node --test test/provider.js`    | Provider sockets, relay slices, protocols, and relay shutdown  |
| `node --test test/cli.js`         | CLI Binding, graceful shutdown, and a taken port exit 1        |
| `npm run test:browser`            | Chrome relay over TURN UDP, then TCP                           |

The codec tests cover RFC 5769 request and IPv4/IPv6 response vectors,
space padding, unknown attributes, integrity and fingerprints, message
types, address round trips, and non-STUN inputs. CI runs on Node.js 22,
24, 25, and 26 on Linux, Windows, and macOS.

Binding tests cover IPv4 and IPv6 responses, required and optional
attributes, malformed input, fragmented and coalesced TCP requests,
idempotent shutdown with live clients, port reuse, and cleanup after a
partial bind failure. They bind port zero or a port reserved by the test
and await cleanup. Hosts without IPv6 test the listener rejection instead
of running the round trips.

TURN tests preserve the saved authentication, integrity coverage, private
address, replay, lifetime and rate cases. They also check pending replays,
transaction collisions, bounded caching, close races and current allocation
stats without sockets. UDP tests check real challenge/allocation, Send/Data,
IP-only permissions, channels in both directions, errors, quotas, occupied
ports, range exhaustion, Refresh, expiry, relay cleanup and listener failure
during a pending allocation. TCP tests check the same protocol over a
stream, ChannelData whose length is not a multiple of 4, padding that is
not delivered as payload, fragmented and coalesced frames, allocation
removal when the connection closes, and one Allocate plus ChannelData
round trip over TLS with a `node:tls` client. Provider tests drive the
same Binding, Allocate, and ChannelData path through `connection` and
`datagram` on TCP, an already-decrypted TLS socket, and UDP, and check
relay-port slices, disabled TURN, and relay shutdown. `npm run test:browser`
serves a page on `127.0.0.1` and checks two relay-only peer connections:
a data channel message arrives, and the selected pair's local candidate
is `relay` on both sides, first over TURN UDP and then over TCP. Chrome
is `CHROME_BIN` or `/usr/bin/google-chrome`, launched with
`--allow-loopback-in-peer-connection`. Every socket fixture uses
port zero or selected free ports and awaits cleanup; relay ranges are
reserved by the tests.

## License

[MIT](LICENSE).
