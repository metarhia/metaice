# Changelog

## Unreleased

- Export `isPrivate(address)`, the private address policy of relay peers,
  from the package and its typings.
- Add an impress provider: `start` with `context.thread` returns
  `{ connection, datagram, stop }` without binding, slices relay ports,
  honors `context.protocols`, and sweeps allocations while TURN is on.
  Export `protocols` and declare the same list in `package.json`.
- Add a `metaice` CLI that loads `.js` or `.json` options, logs the bound
  ports, and closes once on SIGINT or SIGTERM.
- Add `start(options, context)` for the CLI: without `context.thread` it
  listens and returns `{ stop }`.
- Add TURN over TCP and TLS with stream framing, padded ChannelData,
  allocation removal when the connection closes, and PEM certificates.
- Add a Chrome relay test: a data channel and selected relay candidates
  over TURN UDP, then TCP.
- Add authenticated UDP TURN allocations, permissions, channels, Send/Data
  indications, refresh, replay protection, expiry, quotas and rate limits.
- Add TURN REST credentials, stateless address-bound nonces, browser ICE
  server lists and TypeScript helper and server option declarations.
- Track pending relay opens and already-closing allocations through awaited
  shutdown and listener failures; report live allocation stats and safe logs.
- Port TURN security and UDP relay tests with selected free relay ranges,
  and add credential, replay collision and shutdown race regressions.

- Add `IceServer` with owned UDP4, UDP6, and TCP listeners, STUN Binding,
  shared ephemeral ports, bind failure cleanup, idempotent shutdown, and
  TypeScript declarations.
- Add Binding tests for addresses, unknown attributes, TCP framing, live
  connection cleanup, and listener port reuse.
- Add the STUN codec with message types, ordered attributes, IPv4 and IPv6
  XOR addresses, MESSAGE-INTEGRITY, FINGERPRINT, and long-term keys.
- Add TypeScript declarations, RFC 5769 vector tests, and package tooling
  for Node.js 22 and later.
