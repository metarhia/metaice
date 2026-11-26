'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const helpers = require('./turn-helpers.js');
const { credentials, iceServers, isPrivate } = require('../metaice.js');
const { createNonce } = require('../lib/credentials.js');

const { loadIce, turnOptions, clientAuth, packet, codeOf, TRANSPORT } = helpers;
const REMOTE = { address: '127.0.0.1', port: 50000, family: 'IPv4' };

const fixture = (t, options = turnOptions()) => {
  const loaded = loadIce(options);
  t.after(() => loaded.ice.close());
  const packets = [];
  const socket = {
    transport: 'udp4',
    socket: {
      address: () => ({ address: '0.0.0.0', port: 3478 }),
      send: (buffer) => packets.push(buffer),
    },
  };
  const { ice } = loaded;
  const auth = clientAuth(ice, 'peer');
  const exchange = async (method, values, identity = auth, options = {}) => {
    const buffer = packet(method, values, identity, options);
    await ice.receive(socket, buffer, REMOTE);
    return packets.at(-1);
  };
  return { ...loaded, socket, packets, auth, exchange };
};

const verify = (stun, buffer, key, code = 0) => {
  const message = stun.decode(buffer);
  assert.equal(codeOf(buffer), code);
  assert.equal(stun.verifyFingerprint(buffer, message), true);
  assert.equal(stun.verifyIntegrity(buffer, message, key), true);
};

test('TURN defaults and options keep STUN independent', async (t) => {
  const { config, packets, exchange, stun } = fixture(t, {});
  assert.equal(config.secret, '');
  assert.equal(config.publicAddress, '');
  assert.equal(config.allowPrivatePeers, false);
  assert.equal(config.port, 3478);
  assert.equal(config.relayPorts[0], 49160);
  assert.equal(config.relayPorts[1], 49359);
  await exchange('allocate', [TRANSPORT], null);
  assert.equal(packets.length, 0);
  const binding = await exchange('binding', [], null);
  assert.equal(stun.decode(binding).kind, 'success');
  assert.equal(
    iceServers({ ...config, peer: 'peer', name: 'localhost' }).length,
    1,
  );
  const loaded = loadIce({ allowPrivatePeers: false });
  assert.equal(loaded.config.allowPrivatePeers, false);
});

test('TURN authentication rejects invalid identities and nonces', async (t) => {
  const { ice, stun, auth, exchange, config } = fixture(t);
  assert.equal(codeOf(await exchange('allocate', [], null)), 401);
  const identities = [
    { ...auth, username: 'malformed' },
    { ...auth, username: '1:peer' },
    { ...auth, realm: 'other' },
    { ...auth, key: crypto.randomBytes(16) },
  ];
  for (const identity of identities) {
    const buffer = await exchange('allocate', [TRANSPORT], identity);
    assert.equal(codeOf(buffer), 401);
  }
  const nonce = createNonce(config.secret, '127.0.0.1', Date.now() - 601000);
  verify(
    stun,
    await exchange('allocate', [TRANSPORT], {
      ...auth,
      nonce,
    }),
    auth.key,
    438,
  );
  verify(
    stun,
    await exchange('allocate', [TRANSPORT], {
      ...auth,
      nonce: createNonce(config.secret, '127.0.0.2'),
    }),
    auth.key,
    438,
  );
  verify(
    stun,
    await exchange('allocate', [TRANSPORT], {
      ...auth,
      nonce: crypto.randomBytes(80).toString('base64url'),
    }),
    auth.key,
    438,
  );
  const identity = credentials({ ...config, peer: 'peer' });
  const expected = crypto
    .createHmac('sha1', config.secret)
    .update(identity.username)
    .digest('base64');
  assert.equal(identity.credential, expected);
  assert.equal(ice.allocations.size, 0);
});

test('authenticated errors retain integrity and fingerprint', async (t) => {
  const { stun, auth, exchange } = fixture(t);
  verify(stun, await exchange('allocate', []), auth.key, 400);
  const tcp = { type: 0x0019, value: Buffer.from([6, 0, 0, 0]) };
  verify(stun, await exchange('allocate', [tcp]), auth.key, 442);
  const family = { type: 0x0017, value: Buffer.from([2, 0, 0, 0]) };
  verify(stun, await exchange('allocate', [TRANSPORT, family]), auth.key, 440);
  const unknown = { type: 0x1234, value: Buffer.alloc(0) };
  const reply = await exchange('allocate', [TRANSPORT, unknown]);
  verify(stun, reply, auth.key, 420);
  assert.equal(
    stun.find(stun.decode(reply), 0x000a).value.readUInt16BE(0),
    0x1234,
  );
  verify(stun, await exchange('refresh', []), auth.key, 437);
});

test('only integrity-covered attributes affect TURN state', async (t) => {
  const { ice, stun, socket, packets, auth } = fixture(t);
  const signed = packet('allocate', [], auth);
  const message = stun.decode(signed);
  const integrity = stun.find(message, 0x0008);
  const end = integrity.offset + 24;
  const bytes = signed.subarray(0, end);
  const transport = stun.attribute(TRANSPORT.type, TRANSPORT.value);
  const forged = Buffer.concat([bytes, transport]);
  forged.writeUInt16BE(forged.length - 20, 2);
  await ice.receive(socket, forged, REMOTE);
  verify(stun, packets.at(-1), auth.key, 400);
  assert.equal(ice.allocations.size, 0);
  const unsigned = packet('refresh', [], null);
  const tail = signed.subarray(20, end);
  const invalid = Buffer.concat([unsigned.subarray(0, 20), tail]);
  invalid.writeUInt16BE(invalid.length - 20, 2);
  await ice.receive(socket, invalid, REMOTE);
  assert.equal(codeOf(packets.at(-1)), 401);
});

test('private peer policy covers IPv4, IPv6 and mapped addresses', () => {
  const blocked = [
    '0.0.0.0',
    '0.1.2.3',
    '10.1.2.3',
    '100.64.1.1',
    '127.0.0.1',
    '169.254.1.1',
    '172.16.2.3',
    '192.168.1.2',
    '224.0.0.1',
    '255.255.255.255',
    '::',
    '::1',
    'fc00::1',
    'fd00::1',
    'fe80::1',
    'ff02::1',
    '::ffff:127.0.0.1',
    '::ffff:8.8.8.8',
    'localhost',
  ];
  for (const address of blocked) assert.equal(isPrivate(address), true);
  assert.equal(isPrivate('8.8.8.8'), false);
  assert.equal(isPrivate('2001:4860:4860::8888'), false);
});

test('UDP allocation replay, ownership, expiry and bounded rate', async (t) => {
  const { ice, stun, config, auth, exchange, socket, packets, logs } =
    fixture(t);
  const sends = [];
  let closed = 0;
  ice.openRelay = async (allocation) => {
    allocation.port = 45000;
    return {
      close: (done) => {
        closed++;
        done();
      },
      send: (data, port, address, done) => {
        sends.push({ data, port, address });
        done(null);
      },
    };
  };
  const transactionId = crypto.randomBytes(12);
  const success = await exchange('allocate', [TRANSPORT], auth, {
    transactionId,
  });
  verify(stun, success, auth.key);
  const replay = await exchange('allocate', [TRANSPORT], auth, {
    transactionId,
  });
  assert.equal(success.equals(replay), true);
  verify(stun, await exchange('allocate', [TRANSPORT]), auth.key, 437);
  const other = clientAuth(ice, 'other');
  verify(stun, await exchange('refresh', [], other), other.key, 441);
  const allocation = ice.allocations.values().next().value;
  const requestId = crypto.randomBytes(12);
  const peer = helpers.peerAttribute(requestId, 42000);
  const permission = await exchange('createPermission', [peer], auth, {
    transactionId: requestId,
  });
  verify(stun, permission, auth.key);
  assert.equal(allocation.permissions.has('127.0.0.1'), true);
  assert.equal(allocation.take(config.relayBitrate / 8 + 1), false);
  assert.ok(allocation.dropped > 0);
  const previous = packets.length;
  const sendId = crypto.randomBytes(12);
  const destination = helpers.peerAttribute(sendId, 43000);
  const data = { type: 0x0013, value: Buffer.from('payload') };
  const indication = packet('send', [destination, data], null, {
    transactionId: sendId,
    kind: 'indication',
  });
  await ice.receive(socket, indication, REMOTE);
  assert.equal(sends[0].port, 43000);
  assert.equal(sends[0].data.toString(), 'payload');
  assert.equal(packets.length, previous);
  allocation.fromPeer(Buffer.from('reply'), REMOTE);
  const stats = ice.stats();
  assert.equal(stats.allocations, 1);
  assert.equal(stats.sent, 7);
  assert.equal(stats.received, 5);
  assert.equal(stats.dropped, allocation.dropped);
  stats.sent = 0;
  assert.equal(ice.stats().sent, 7);
  allocation.permissions.set('127.0.0.1', Date.now() - 1);
  await ice.receive(socket, indication, REMOTE);
  assert.equal(sends.length, 1);
  allocation.expires = Date.now() - 1;
  ice.sweep();
  await new Promise((resolve) => {
    setImmediate(resolve);
  });
  assert.equal(ice.allocations.size, 0);
  assert.equal(closed, 1);
  assert.deepEqual(ice.stats(), {
    allocations: 0,
    sent: 0,
    received: 0,
    dropped: 0,
  });
  assert.equal(logs.length, 2);
  assert.match(logs[0], /^TURN create peer=peer client=udp relay=udp:/);
  assert.match(logs[1], /^TURN delete peer=peer client=udp relay=udp:/);
  const hidden = [auth.username, auth.key.toString('hex'), 'payload', 'reply'];
  const credential = credentials({ ...config, peer: 'peer' }).credential;
  hidden.push(credential);
  for (const value of hidden) {
    assert.equal(
      logs.some((line) => line.includes(value)),
      false,
    );
  }
  assert.equal(
    logs.some((line) => line.includes(config.secret)),
    false,
  );
  assert.equal(
    logs.some((line) => line.includes(auth.nonce)),
    false,
  );
  ice.sweep(Date.now() + 41000);
  assert.equal(ice.responses.size, 0);
});

test('Pending Allocate replay shares one bind and response', async (t) => {
  const { ice, stun, socket, packets, auth } = fixture(t);
  const { promise, resolve } = Promise.withResolvers();
  let binds = 0;
  ice.openRelay = async (allocation) => {
    binds++;
    allocation.port = 45000;
    await promise;
    return { close: (done) => done() };
  };
  const request = packet('allocate', [TRANSPORT], auth);
  const first = ice.receive(socket, request, REMOTE);
  const repeated = ice.receive(socket, request, REMOTE);
  assert.equal(binds, 1);
  const another = packet('allocate', [TRANSPORT], auth);
  await ice.receive(socket, another, REMOTE);
  verify(stun, packets.at(-1), auth.key, 437);
  resolve();
  await Promise.all([first, repeated]);
  assert.equal(packets.at(-1).equals(packets.at(-2)), true);
  assert.equal(ice.allocations.size, 1);
  await ice.close();
  assert.equal(ice.allocations.size, 0);
});

test('Permissions enforce family, atomicity and integrity', async (t) => {
  const f = fixture(t, turnOptions(false));
  const { ice, stun, auth, exchange, socket, packets } = f;
  ice.openRelay = async (allocation) => {
    allocation.port = 45000;
    return { close: (done) => done() };
  };
  await exchange('allocate', [TRANSPORT]);
  const allocation = ice.allocations.values().next().value;
  const transactionId = crypto.randomBytes(12);
  const publicPeer = helpers.peerAttribute(transactionId, 9000, '198.51.100.1');
  const privatePeer = helpers.peerAttribute(transactionId, 9000, '192.168.0.1');
  verify(
    stun,
    await exchange('createPermission', [publicPeer, privatePeer], auth, {
      transactionId,
    }),
    auth.key,
    403,
  );
  assert.equal(allocation.permissions.size, 0);
  const v6Id = crypto.randomBytes(12);
  const ipv6 = helpers.peerAttribute(v6Id, 9000, '2001:db8::1');
  verify(
    stun,
    await exchange('createPermission', [ipv6], auth, {
      transactionId: v6Id,
    }),
    auth.key,
    443,
  );
  const forgedId = crypto.randomBytes(12);
  const forgedPeer = helpers.peerAttribute(forgedId, 9000, '198.51.100.1');
  const signed = packet('createPermission', [], auth, {
    transactionId: forgedId,
  });
  const decoded = stun.decode(signed);
  const integrity = stun.find(decoded, 0x0008);
  const prefix = signed.subarray(0, integrity.offset + 24);
  const forged = Buffer.concat([
    prefix,
    stun.attribute(0x0012, forgedPeer.value),
  ]);
  forged.writeUInt16BE(forged.length - 20, 2);
  await ice.receive(socket, forged, REMOTE);
  verify(stun, packets.at(-1), auth.key, 400);
  assert.equal(allocation.permissions.size, 0);
  const expiry = allocation.expires;
  const invalid = packet(
    'refresh',
    [{ type: 0x000d, value: Buffer.alloc(4) }],
    { ...auth, key: crypto.randomBytes(16) },
  );
  await ice.receive(socket, invalid, REMOTE);
  assert.equal(codeOf(packets.at(-1)), 401);
  assert.equal(ice.allocations.size, 1);
  assert.equal(allocation.expires, expiry);
  const permittedId = crypto.randomBytes(12);
  const permitted = helpers.peerAttribute(permittedId, 9000, '198.51.100.1');
  verify(
    stun,
    await exchange('createPermission', [permitted], auth, {
      transactionId: permittedId,
    }),
    auth.key,
  );
  assert.equal(allocation.permissions.size, 1);
  const mappedId = crypto.randomBytes(12);
  const mapped = helpers.peerAttribute(mappedId, 9000, '::ffff:808:808');
  verify(
    stun,
    await exchange('createPermission', [mapped], auth, {
      transactionId: mappedId,
    }),
    auth.key,
    403,
  );
  assert.equal(allocation.permissions.size, 1);
  await ice.close();
});

test('close waits for pending Allocate and replay cleanup', async (t) => {
  const { ice, auth, socket, packets } = fixture(t);
  const opening = Promise.withResolvers();
  let closed = 0;
  ice.openRelay = async (allocation) => {
    allocation.port = 45000;
    await opening.promise;
    return {
      close: (done) => {
        closed++;
        done();
      },
    };
  };
  const buffer = packet('allocate', [TRANSPORT], auth);
  const first = ice.receive(socket, buffer, REMOTE);
  const replay = ice.receive(socket, buffer, REMOTE);
  const closing = ice.close();
  assert.equal(ice.close(), closing);
  assert.equal(ice.allocations.size, 0);
  assert.equal(closed, 0);
  assert.equal(ice.closingAllocations.size, 1);
  opening.resolve();
  await Promise.all([first, replay, closing]);
  assert.equal(closed, 1);
  assert.equal(packets.length, 0);
  assert.equal(ice.closingAllocations.size, 0);
  assert.equal(ice.pendingRequests.size, 0);
  assert.equal(ice.responses.size, 0);
  assert.equal(ice.timer, null);
});

test('close awaits allocations already removed by sweep', async (t) => {
  const { ice, exchange } = fixture(t);
  const closing = Promise.withResolvers();
  let finish = null;
  let closed = 0;
  ice.openRelay = async (allocation) => {
    allocation.port = 45000;
    return {
      close: (done) => {
        finish = done;
        closed++;
      },
    };
  };
  await exchange('allocate', [TRANSPORT]);
  const allocation = ice.allocations.values().next().value;
  allocation.expires = Date.now() - 1;
  ice.sweep();
  assert.equal(ice.allocations.size, 0);
  assert.equal(ice.closingAllocations.size, 1);
  const shutdown = async () => {
    await ice.close();
    closing.resolve();
  };
  const stopped = shutdown();
  await new Promise((resolve) => {
    setImmediate(resolve);
  });
  assert.equal(closed, 1);
  assert.equal(ice.closingAllocations.size, 1);
  assert.equal(allocation.close(), allocation.close());
  finish();
  await stopped;
  await closing.promise;
  assert.equal(ice.closingAllocations.size, 0);
});

test('failed relay opens release allocation ownership', async (t) => {
  const { ice, stun, auth, exchange } = fixture(t);
  ice.openRelay = async () => {
    throw new Error('relay bind failed');
  };
  verify(stun, await exchange('allocate', [TRANSPORT]), auth.key, 508);
  assert.equal(ice.allocations.size, 0);
  assert.equal(ice.closingAllocations.size, 0);
  assert.deepEqual(ice.stats(), {
    allocations: 0,
    sent: 0,
    received: 0,
    dropped: 0,
  });
});

test('transaction collisions drop and cache stays bounded', async (t) => {
  const { ice, stun, socket, auth, packets, exchange } = fixture(t);
  const transactionId = crypto.randomBytes(12);
  const first = await exchange('allocate', [], auth, { transactionId });
  verify(stun, first, auth.key, 400);
  const count = packets.length;
  await exchange('allocate', [TRANSPORT], auth, { transactionId });
  assert.equal(packets.length, count);
  const collision = packet('refresh', [], null, { transactionId });
  await ice.receive(socket, collision, REMOTE);
  assert.equal(packets.length, count);
  const end = 8192 - ice.responses.size;
  for (let i = 0; i < end; i++) {
    await exchange('allocate', []);
  }
  assert.equal(ice.responses.size, 8192);
  const before = packets.length;
  await exchange('refresh', []);
  assert.equal(packets.length, before);
  ice.sweep(Date.now() + 41000);
  assert.equal(ice.responses.size, 0);
});
