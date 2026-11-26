'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const dgram = require('node:dgram');
const fs = require('node:fs/promises');
const net = require('node:net');
const path = require('node:path');
const tls = require('node:tls');
const { setTimeout: delay } = require('node:timers/promises');
const { once } = require('node:events');

const helpers = require('./turn-helpers.js');
const { createNonce } = require('../lib/credentials.js');

const { loadIce, turnOptions, clientAuth, packet, codeOf, TRANSPORT } = helpers;
const { expectCode, requestPeer, channelNumber, channelPacket } = helpers;
const { closeUdp, closeServer, reservePort, reserveRange } = helpers;
const TLS_PATHS = {
  key: path.join(__dirname, 'fixtures/turn-key.pem'),
  cert: path.join(__dirname, 'fixtures/turn-cert.pem'),
};

const reserveTcp = async (t) => {
  const server = net.createServer();
  t.after(() => closeServer(server));
  const ready = once(server, 'listening');
  server.listen(0, '127.0.0.1');
  await ready;
  const port = server.address().port;
  const release = () => closeServer(server);
  return { port, release };
};

const waitFor = async (predicate) => {
  for (let i = 0; i < 100; i++) {
    if (predicate()) return;
    await delay(10);
  }
  assert.fail('Server cleanup did not complete');
};

const udp = async (t, port = 0) => {
  const socket = dgram.createSocket('udp4');
  let pending = null;
  const queue = [];
  socket.on('message', (buffer) => {
    if (pending) {
      const current = pending;
      pending = null;
      clearTimeout(current.timer);
      current.resolve(buffer);
    } else {
      queue.push(buffer);
    }
  });
  t.after(() => closeUdp(socket));
  const ready = once(socket, 'listening');
  socket.bind(port, '127.0.0.1');
  await ready;
  const next = (timeoutMs = 2000) => {
    if (queue.length) return Promise.resolve(queue.shift());
    const { promise, resolve, reject } = Promise.withResolvers();
    const timer = setTimeout(() => {
      pending = null;
      reject(new Error('UDP response timeout'));
    }, timeoutMs);
    pending = { resolve, timer };
    return promise;
  };
  const send = (buffer, destination) => {
    socket.send(buffer, destination, '127.0.0.1');
  };
  return { socket, next, send, port: socket.address().port };
};

const stream = async (t, port, tlsOptions = null) => {
  const options = { port, host: '127.0.0.1', ...tlsOptions };
  const socket = tlsOptions ? tls.connect(options) : net.connect(options);
  const errors = [];
  const queue = [];
  let pending = null;
  let buffer = Buffer.alloc(0);
  socket.on('error', (error) => {
    errors.push(error);
    if (pending) {
      clearTimeout(pending.timer);
      pending.reject(error);
      pending = null;
    }
  });
  const closed = new Promise((resolve) => {
    socket.once('close', resolve);
  });
  const close = async () => {
    socket.destroy();
    await closed;
  };
  t.after(close);
  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length >= 4) {
      const isChannel = buffer[0] >= 0x40 && buffer[0] <= 0x4f;
      const size = buffer.readUInt16BE(2);
      const length = isChannel ? 4 + Math.ceil(size / 4) * 4 : 20 + size;
      if (buffer.length < length) return;
      const frame = buffer.subarray(0, length);
      buffer = buffer.subarray(length);
      if (pending) {
        const current = pending;
        pending = null;
        clearTimeout(current.timer);
        current.resolve(frame);
      } else {
        queue.push(frame);
      }
    }
  });
  await once(socket, tlsOptions ? 'secureConnect' : 'connect');
  socket.setNoDelay(true);
  const next = (timeoutMs = 2000) => {
    if (queue.length) return Promise.resolve(queue.shift());
    const { promise, resolve, reject } = Promise.withResolvers();
    const timer = setTimeout(() => {
      pending = null;
      reject(new Error('stream response timeout'));
    }, timeoutMs);
    pending = { resolve, reject, timer };
    return promise;
  };
  const send = (buffer) => socket.write(buffer);
  return { socket, next, send, port: socket.localPort, closed, close, errors };
};

const fixture = async (t, allowPrivate = true, release = null) => {
  const reservations = await reserveRange(t, 4);
  const loaded = loadIce({
    ...turnOptions(allowPrivate),
    allowPrivatePeers: allowPrivate || undefined,
    port: 0,
    listen: '127.0.0.1',
    relayPorts: reservations.range,
  });
  const { ice, stun } = loaded;
  t.after(async () => {
    if (release) release();
    await ice.close();
  });
  await ice.listen();
  const port = ice.ports.udp;
  const client = await stream(t, ice.ports.tcp);
  const peer = await udp(t);
  const auth = clientAuth(ice, 'socket-peer');
  const exchange = async (
    method,
    attributes,
    identity = auth,
    options = {},
  ) => {
    const buffer = packet(method, attributes, identity, options);
    const reply = client.next();
    client.send(buffer, port);
    return reply;
  };
  const allocate = async () => {
    const reply = await exchange('allocate', [TRANSPORT]);
    assert.equal(codeOf(reply), 0);
    const message = stun.decode(reply);
    assert.equal(stun.verifyIntegrity(reply, message, auth.key), true);
    assert.equal(stun.verifyFingerprint(reply, message), true);
    return stun.readAddress(
      stun.find(message, 0x0016).value,
      message.transactionId,
    );
  };
  await reservations.release();
  return { ...loaded, client, peer, auth, port, exchange, allocate };
};

test(
  'TURN TCP socket lifecycle and protocol',
  { timeout: 45000 },
  async (t) => {
    await t.test(
      'TCP challenge, allocation replay and source mapping',
      async (t) => {
        const { ice, stun, client, auth, port, exchange } = await fixture(t);
        const binding = await exchange('binding', [], null);
        assert.equal(stun.decode(binding).kind, 'success');
        const challenge = await exchange('allocate', [TRANSPORT], null);
        expectCode(challenge, 401);
        const nonce = stun
          .find(stun.decode(challenge), 0x0015)
          .value.toString();
        const identity = { ...auth, nonce };
        const transactionId = crypto.randomBytes(12);
        const success = await exchange('allocate', [TRANSPORT], identity, {
          transactionId,
        });
        expectCode(success, 0, auth.key);
        const repeated = await exchange('allocate', [TRANSPORT], identity, {
          transactionId,
        });
        assert.equal(success.equals(repeated), true);
        expectCode(await exchange('allocate', [TRANSPORT]), 437, auth.key);
        assert.equal(ice.allocations.size, 1);
        const message = stun.decode(success);
        const mapped = stun.readAddress(
          stun.find(message, 0x0020).value,
          message.transactionId,
        );
        assert.equal(mapped.port, client.port);
        assert.equal(
          ice.listeners.some((item) => item.socket.address().port === port),
          true,
        );
      },
    );

    await t.test(
      'permission IP, Send/Data and channels in both directions',
      async (t) => {
        const f = await fixture(t);
        const { ice, stun, client, peer, auth, port, exchange, allocate } = f;
        const relay = await allocate();
        peer.send(Buffer.from('unauthorized'), relay.port);
        await assert.rejects(client.next(100), /timeout/);
        const send = requestPeer(peer.port, [
          { type: 0x0013, value: Buffer.from('send') },
        ]);
        client.send(
          packet('send', send.attributes, null, {
            transactionId: send.transactionId,
            kind: 'indication',
          }),
          port,
        );
        await assert.rejects(peer.next(100), /timeout/);
        const permission = requestPeer(peer.port);
        expectCode(
          await exchange(
            'createPermission',
            permission.attributes,
            auth,
            permission,
          ),
          0,
          auth.key,
        );
        const peerReply = peer.next();
        client.send(
          packet('send', send.attributes, null, {
            transactionId: send.transactionId,
            kind: 'indication',
          }),
          port,
        );
        assert.equal((await peerReply).toString(), 'send');
        const dataReply = client.next();
        peer.send(Buffer.from('data'), relay.port);
        const dataMessage = stun.decode(await dataReply);
        assert.equal(dataMessage.method, stun.METHODS.data);
        assert.equal(stun.find(dataMessage, 0x0013).value.toString(), 'data');
        const secondPeer = await udp(t);
        const otherReply = client.next();
        secondPeer.send(Buffer.from('same-IP'), relay.port);
        const otherMessage = stun.decode(await otherReply);
        const mapped = stun.readAddress(
          stun.find(otherMessage, 0x0012).value,
          otherMessage.transactionId,
        );
        assert.equal(mapped.port, secondPeer.port);
        const binding = requestPeer(peer.port, [channelNumber(0x4000)]);
        expectCode(
          await exchange('channelBind', binding.attributes, auth, binding),
          0,
          auth.key,
        );
        const channelReply = peer.next();
        client.send(channelPacket(0x4000, Buffer.from('odd'), true), port);
        assert.equal((await channelReply).toString(), 'odd');
        const reverse = client.next();
        peer.send(Buffer.from('back!'), relay.port);
        const frame = await reverse;
        assert.equal(frame.readUInt16BE(0), 0x4000);
        assert.equal(frame.readUInt16BE(2), 5);
        assert.equal(frame.length, 12);
        assert.equal(frame.subarray(4, 9).toString(), 'back!');
        assert.deepEqual(frame.subarray(9), Buffer.alloc(3));
        const channelConflict = requestPeer(secondPeer.port, [
          channelNumber(0x4000),
        ]);
        expectCode(
          await exchange(
            'channelBind',
            channelConflict.attributes,
            auth,
            channelConflict,
          ),
          400,
          auth.key,
        );
        const peerConflict = requestPeer(peer.port, [channelNumber(0x4001)]);
        expectCode(
          await exchange(
            'channelBind',
            peerConflict.attributes,
            auth,
            peerConflict,
          ),
          400,
          auth.key,
        );
        const allocation = ice.allocations.values().next().value;
        allocation.permissions.set('127.0.0.1', Date.now() - 1);
        client.send(channelPacket(0x4000, Buffer.from('expired'), true), port);
        await assert.rejects(peer.next(100), /timeout/);
        peer.send(Buffer.from('expired'), relay.port);
        await assert.rejects(client.next(100), /timeout/);
        const rebound = requestPeer(peer.port, [channelNumber(0x4000)]);
        expectCode(
          await exchange('channelBind', rebound.attributes, auth, rebound),
          0,
          auth.key,
        );
        allocation.channels.get(0x4000).expires = Date.now() - 1;
        client.send(channelPacket(0x4000, Buffer.from('expired'), true), port);
        await assert.rejects(peer.next(100), /timeout/);
        allocation.tokens = 0;
        allocation.sampled = Date.now() + 10000;
        client.send(
          packet('send', send.attributes, null, {
            transactionId: send.transactionId,
            kind: 'indication',
          }),
          port,
        );
        await assert.rejects(peer.next(100), /timeout/);
        assert.ok(allocation.dropped > 0);
        const stats = ice.stats();
        assert.equal(stats.allocations, 1);
        assert.equal(stats.sent, 7);
        assert.equal(stats.received, 16);
        assert.equal(stats.dropped, allocation.dropped);
        const lifetime = Buffer.alloc(4);
        expectCode(
          await exchange('refresh', [{ type: 0x000d, value: lifetime }]),
          0,
          auth.key,
        );
        assert.equal(ice.allocations.size, 0);
        assert.equal(ice.relayPorts.size, 0);
        assert.deepEqual(ice.stats(), {
          allocations: 0,
          sent: 0,
          received: 0,
          dropped: 0,
        });
        assert.equal(f.logs.length, 2);
        const hidden = [f.config.secret, auth.username, auth.nonce];
        for (const value of hidden) {
          assert.equal(
            f.logs.some((line) => line.includes(value)),
            false,
          );
        }
        expectCode(await exchange('refresh', []), 437, auth.key);
      },
    );

    await t.test(
      'authentication, private peers and required errors',
      async (t) => {
        const { ice, auth, peer, exchange, allocate } = await fixture(t, false);
        const wrong = { ...auth, key: crypto.randomBytes(16) };
        expectCode(await exchange('allocate', [TRANSPORT], wrong), 401);
        const stale = {
          ...auth,
          nonce: createNonce(
            ice.options.secret,
            '127.0.0.1',
            Date.now() - 601000,
          ),
        };
        expectCode(
          await exchange('allocate', [TRANSPORT], stale),
          438,
          auth.key,
        );
        await allocate();
        const permission = requestPeer(peer.port);
        expectCode(
          await exchange(
            'createPermission',
            permission.attributes,
            auth,
            permission,
          ),
          403,
          auth.key,
        );
        const identity = clientAuth(ice, 'wrong-owner');
        expectCode(await exchange('refresh', [], identity), 441, identity.key);
        expectCode(await exchange('channelBind', []), 400, auth.key);
      },
    );

    await t.test(
      'quota, occupied ports, exhaustion, refresh and shutdown',
      async (t) => {
        const reserved = await reserveRange(t, 2);
        const occupied = reserved.sockets[0];
        const occupiedPort = occupied.address().port;
        const f = await fixture(t);
        await closeUdp(reserved.sockets[1]);
        const { ice, stun, config, auth, port, exchange, allocate } = f;
        config.relayPorts = reserved.range;
        config.allocationsPerPeer = 1;
        const relay = await allocate();
        assert.equal(relay.port, occupiedPort + 1);
        const other = await stream(t, ice.ports.tcp);
        const request = packet('allocate', [TRANSPORT], auth);
        const reply = other.next();
        other.send(request, port);
        expectCode(await reply, 486, auth.key);
        const secondAuth = clientAuth(ice, 'second-peer');
        const exhausted = other.next();
        other.send(packet('allocate', [TRANSPORT], secondAuth), port);
        expectCode(await exhausted, 508, secondAuth.key);
        const lifetime = Buffer.alloc(4);
        lifetime.writeUInt32BE(0xffffffff);
        const refreshed = await exchange('refresh', [
          { type: 0x000d, value: lifetime },
        ]);
        expectCode(refreshed, 0, auth.key);
        assert.equal(
          stun.find(stun.decode(refreshed), 0x000d).value.readUInt32BE(0),
          config.allocationLifetime[1],
        );
        const allocation = ice.allocations.values().next().value;
        allocation.expires = Date.now() - 1;
        ice.sweep();
        await new Promise((resolve) => {
          setImmediate(resolve);
        });
        assert.equal(ice.allocations.size, 0);
        await ice.close();
        assert.equal(ice.listeners.length, 0);
        assert.equal(ice.timer, null);
        assert.equal(ice.relayPorts.size, 0);
        assert.equal(ice.responses.size, 0);
      },
    );
  },
);

test(
  'TCP pending replay shares a relay and drops collisions',
  { timeout: 10000 },
  async (t) => {
    const opening = Promise.withResolvers();
    const release = () => opening.resolve();
    const f = await fixture(t, true, release);
    const { ice, client, auth, port } = f;
    const started = Promise.withResolvers();
    let binds = 0;
    let received = 0;
    const dispatch = ice.dispatch.bind(ice);
    ice.dispatch = async (client, buffer, remote) => {
      received++;
      return dispatch(client, buffer, remote);
    };
    ice.openRelay = async (allocation) => {
      binds++;
      started.resolve();
      await opening.promise;
      return allocation.openRelay();
    };
    const transactionId = crypto.randomBytes(12);
    const request = packet('allocate', [TRANSPORT], auth, {
      transactionId,
    });
    client.send(request, port);
    await started.promise;
    client.send(request, port);
    const collision = packet('allocate', [], auth, { transactionId });
    client.send(collision, port);
    await delay(30);
    assert.equal(received, 1);
    assert.equal(binds, 1);
    assert.equal(ice.allocations.size, 1);
    opening.resolve();
    const first = await client.next();
    const repeated = await client.next();
    expectCode(first, 0, auth.key);
    assert.deepEqual(repeated, first);
    await assert.rejects(client.next(100), /timeout/);
    assert.equal(binds, 1);
    assert.equal(received, 3);
  },
);

test(
  'TCP integrity tails cannot allocate, permit or delete',
  { timeout: 10000 },
  async (t) => {
    const { ice, stun, client, auth, port, exchange, allocate } =
      await fixture(t);
    const signed = packet('allocate', [], auth);
    const decoded = stun.decode(signed);
    const integrity = stun.find(decoded, 0x0008);
    const tail = stun.attribute(TRANSPORT.type, TRANSPORT.value);
    const forged = Buffer.concat([
      signed.subarray(0, integrity.offset + 24),
      tail,
    ]);
    forged.writeUInt16BE(forged.length - 20, 2);
    client.send(forged, port);
    expectCode(await client.next(), 400, auth.key);
    assert.equal(ice.allocations.size, 0);
    await allocate();
    const transactionId = crypto.randomBytes(12);
    const peer = helpers.peerAttribute(transactionId, client.port);
    const request = packet('createPermission', [], auth, {
      transactionId,
    });
    const message = stun.decode(request);
    const signedEnd = stun.find(message, 0x0008).offset + 24;
    const permission = Buffer.concat([
      request.subarray(0, signedEnd),
      stun.attribute(peer.type, peer.value),
    ]);
    permission.writeUInt16BE(permission.length - 20, 2);
    client.send(permission, port);
    expectCode(await client.next(), 400, auth.key);
    const allocation = ice.allocations.values().next().value;
    assert.equal(allocation.permissions.size, 0);
    const wrong = { ...auth, key: crypto.randomBytes(16) };
    const lifetime = { type: 0x000d, value: Buffer.alloc(4) };
    expectCode(await exchange('refresh', [lifetime], wrong), 401);
    assert.equal(ice.allocations.size, 1);
  },
);

test(
  'TCP permission validation is atomic and blocks mapped peers',
  { timeout: 10000 },
  async (t) => {
    const { ice, auth, exchange, allocate, peer } = await fixture(t, false);
    await allocate();
    const transactionId = crypto.randomBytes(12);
    const allowed = helpers.peerAttribute(
      transactionId,
      peer.port,
      '198.51.100.1',
    );
    const blocked = helpers.peerAttribute(transactionId, peer.port);
    expectCode(
      await exchange('createPermission', [allowed, blocked], auth, {
        transactionId,
      }),
      403,
      auth.key,
    );
    const allocation = ice.allocations.values().next().value;
    assert.equal(allocation.permissions.size, 0);
    const allowedId = crypto.randomBytes(12);
    const publicPeer = helpers.peerAttribute(
      allowedId,
      peer.port,
      '198.51.100.1',
    );
    expectCode(
      await exchange('createPermission', [publicPeer], auth, {
        transactionId: allowedId,
      }),
      0,
      auth.key,
    );
    assert.equal(allocation.permissions.size, 1);
    const mappedId = crypto.randomBytes(12);
    const mapped = helpers.peerAttribute(mappedId, peer.port, '::ffff:808:808');
    expectCode(
      await exchange('createPermission', [mapped], auth, {
        transactionId: mappedId,
      }),
      403,
      auth.key,
    );
    const ipv6Id = crypto.randomBytes(12);
    const ipv6 = helpers.peerAttribute(ipv6Id, peer.port, '2001:db8::1');
    expectCode(
      await exchange('createPermission', [ipv6], auth, {
        transactionId: ipv6Id,
      }),
      443,
      auth.key,
    );
    assert.equal(allocation.permissions.size, 1);
  },
);

test(
  'TCP close awaits an opening relay and releases its port',
  { timeout: 10000 },
  async (t) => {
    const started = Promise.withResolvers();
    const opening = Promise.withResolvers();
    const release = () => opening.resolve();
    const f = await fixture(t, true, release);
    const { ice, client, auth, port, config } = f;
    ice.openRelay = async (allocation) => {
      const relay = await allocation.openRelay();
      started.resolve();
      await opening.promise;
      return relay;
    };
    client.send(packet('allocate', [TRANSPORT], auth), port);
    await started.promise;
    const allocation = ice.allocations.values().next().value;
    const relayPort = allocation.port;
    assert.ok(relayPort > 0);
    const closing = ice.close();
    assert.equal(ice.close(), closing);
    await new Promise((resolve) => {
      setImmediate(resolve);
    });
    assert.equal(ice.closingAllocations.size, 1);
    opening.resolve();
    await closing;
    assert.equal(ice.relayPorts.size, 0);
    assert.equal(ice.pendingRequests.size, 0);
    assert.equal(ice.closingAllocations.size, 0);
    assert.equal(ice.responses.size, 0);
    assert.equal(ice.timer, null);
    const replacement = loadIce({ ...config, port }).ice;
    t.after(() => replacement.close());
    await replacement.listen();
    await replacement.close();
    const relay = await reservePort(relayPort);
    await closeUdp(relay);
    await client.closed;
    assert.deepEqual(client.errors, []);
    await assert.rejects(client.next(100), /timeout/);
  },
);

test('TCP fragmented and coalesced padded frames', async (t) => {
  const { auth, client, peer, exchange, allocate } = await fixture(t);
  const challenge = packet('allocate', [TRANSPORT]);
  const cuts = [1, 3, 11, 23, challenge.length];
  let offset = 0;
  for (const end of cuts) {
    client.send(challenge.subarray(offset, end));
    offset = end;
    await delay(10);
  }
  expectCode(await client.next(), 401);
  const relay = await allocate();
  const binding = requestPeer(peer.port, [channelNumber(0x4000)]);
  expectCode(
    await exchange('channelBind', binding.attributes, auth, binding),
    0,
    auth.key,
  );
  const first = packet('refresh', [], auth);
  const second = packet('binding', []);
  const odd = channelPacket(0x4000, Buffer.from('odd'), true);
  odd[7] = 0xff;
  const five = channelPacket(0x4000, Buffer.from('five!'), true);
  const trailing = channelPacket(0x4000, Buffer.from('partial'), true);
  client.send(
    Buffer.concat([first, odd, second, five, trailing.subarray(0, 2)]),
  );
  expectCode(await client.next(), 0, auth.key);
  expectCode(await client.next(), 0);
  assert.equal((await peer.next()).toString(), 'odd');
  assert.equal((await peer.next()).toString(), 'five!');
  await assert.rejects(peer.next(50), /timeout/);
  client.send(trailing.subarray(2, 5));
  await assert.rejects(peer.next(50), /timeout/);
  client.send(trailing.subarray(5));
  assert.equal((await peer.next()).toString(), 'partial');
  const fragments = channelPacket(0x4000, Buffer.from('split'), true);
  client.send(fragments.subarray(0, 1));
  await delay(10);
  client.send(fragments.subarray(1, 4));
  await assert.rejects(peer.next(50), /timeout/);
  client.send(fragments.subarray(4, 6));
  await assert.rejects(peer.next(50), /timeout/);
  client.send(fragments.subarray(6));
  assert.equal((await peer.next()).toString(), 'split');
  peer.send(Buffer.from('odd'), relay.port);
  peer.send(Buffer.from('five!'), relay.port);
  const back = await client.next();
  assert.equal(back.length, 8);
  assert.equal(back.readUInt16BE(2), 3);
  assert.equal(back.subarray(4, 7).toString(), 'odd');
  assert.equal(back[7], 0);
  const reverse = await client.next();
  assert.equal(reverse.length, 12);
  assert.equal(reverse.readUInt16BE(2), 5);
  assert.equal(reverse.subarray(4, 9).toString(), 'five!');
  expectCode(await exchange('binding', [], null), 0);
});

test('TCP required errors and default private policy', async (t) => {
  const { ice, stun, auth, exchange, allocate } = await fixture(t, false);
  assert.equal(ice.options.allowPrivatePeers, false);
  expectCode(await exchange('refresh', []), 437, auth.key);
  expectCode(await exchange('allocate', []), 400, auth.key);
  const transport = { type: 0x0019, value: Buffer.from([6, 0, 0, 0]) };
  expectCode(await exchange('allocate', [transport]), 442, auth.key);
  const family = { type: 0x0017, value: Buffer.from([2, 0, 0, 0]) };
  expectCode(await exchange('allocate', [TRANSPORT, family]), 440, auth.key);
  const unknown = { type: 0x1234, value: Buffer.alloc(0) };
  const reply = await exchange('allocate', [TRANSPORT, unknown]);
  expectCode(reply, 420, auth.key);
  assert.equal(
    stun.find(stun.decode(reply), 0x000a).value.readUInt16BE(0),
    0x1234,
  );
  const expired = { ...auth, username: '1:expired' };
  expectCode(await exchange('allocate', [TRANSPORT], expired), 401);
  await allocate();
  const invalid = { type: 0x000d, value: Buffer.alloc(3) };
  expectCode(await exchange('refresh', [invalid]), 400, auth.key);
});

test('TCP connection close releases its allocation and relay', async (t) => {
  const { ice, client, allocate } = await fixture(t);
  const relay = await allocate();
  await client.close();
  await waitFor(() => ice.connections.size === 0 && ice.relayPorts.size === 0);
  assert.equal(ice.allocations.size, 0);
  assert.equal(ice.closingConnections.size, 0);
  const reused = await reservePort(relay.port);
  await closeUdp(reused);
  await ice.close();
  assert.deepEqual(client.errors, []);
});

test(
  'TCP disconnected pending allocation stays owned until relay close',
  { timeout: 10000 },
  async (t) => {
    const opening = Promise.withResolvers();
    const release = () => opening.resolve();
    const { ice, client, auth, port } = await fixture(t, true, release);
    const started = Promise.withResolvers();
    ice.openRelay = async (allocation) => {
      const relay = await allocation.openRelay();
      started.resolve();
      await opening.promise;
      return relay;
    };
    client.send(packet('allocate', [TRANSPORT], auth), port);
    await started.promise;
    const allocation = ice.allocations.values().next().value;
    const relayPort = allocation.port;
    await client.close();
    await waitFor(() => ice.connections.size === 0);
    assert.equal(ice.allocations.size, 0);
    assert.equal(ice.closingAllocations.size, 1);
    assert.equal(ice.closingConnections.size, 1);
    let finished = false;
    const closing = ice.close();
    const observed = async () => {
      await closing;
      finished = true;
    };
    const completion = observed();
    await delay(20);
    assert.equal(finished, false);
    opening.resolve();
    await completion;
    assert.equal(ice.relayPorts.size, 0);
    assert.equal(ice.pendingRequests.size, 0);
    assert.equal(ice.closingConnections.size, 0);
    const reused = await reservePort(relayPort);
    await closeUdp(reused);
  },
);

test(
  'TLS verified certificate Allocate and padded ChannelData round trip',
  { timeout: 10000 },
  async (t) => {
    const reserved = await reserveTcp(t);
    const range = await reserveRange(t, 2);
    const { ice, stun, logs } = loadIce({
      ...turnOptions(),
      port: 0,
      listen: '127.0.0.1',
      tlsPort: reserved.port,
      tls: {
        key: path.relative(process.cwd(), TLS_PATHS.key),
        cert: path.relative(process.cwd(), TLS_PATHS.cert),
      },
      relayPorts: range.range,
    });
    t.after(() => ice.close());
    await reserved.release();
    await ice.listen();
    assert.equal(ice.ports.tls, reserved.port);
    assert.equal(ice.ports.udp, ice.ports.tcp);
    await range.release();
    const ca = await fs.readFile(TLS_PATHS.cert);
    const tlsOptions = { ca, servername: 'localhost' };
    const client = await stream(t, ice.ports.tls, tlsOptions);
    assert.equal(client.socket.authorized, true);
    const peer = await udp(t);
    const auth = clientAuth(ice, 'tls-peer');
    client.send(packet('allocate', [TRANSPORT], null));
    const challenge = stun.decode(await client.next());
    auth.nonce = stun.find(challenge, 0x0015).value.toString();
    client.send(packet('allocate', [TRANSPORT], auth));
    const success = await client.next();
    expectCode(success, 0, auth.key);
    const message = stun.decode(success);
    const relay = stun.readAddress(
      stun.find(message, 0x0016).value,
      message.transactionId,
    );
    const binding = requestPeer(peer.port, [channelNumber(0x4000)]);
    client.send(packet('channelBind', binding.attributes, auth, binding));
    expectCode(await client.next(), 0, auth.key);
    client.send(channelPacket(0x4000, Buffer.from('odd'), true));
    assert.equal((await peer.next()).toString(), 'odd');
    peer.send(Buffer.from('five!'), relay.port);
    const frame = await client.next();
    assert.equal(frame.readUInt16BE(0), 0x4000);
    assert.equal(frame.readUInt16BE(2), 5);
    assert.equal(frame.length, 12);
    assert.equal(frame.subarray(4, 9).toString(), 'five!');
    assert.deepEqual(frame.subarray(9), Buffer.alloc(3));
    assert.equal(ice.stats().sent, 3);
    assert.equal(ice.stats().received, 5);
    assert.ok(logs.some((line) => line.includes('client=tls relay=udp:')));
    await client.close();
    await waitFor(() => ice.relayPorts.size === 0 && ice.handshakes.size === 0);
    assert.equal(ice.allocations.size, 0);
    await ice.close();
    const reused = await reservePort(relay.port);
    await closeUdp(reused);
    const listener = net.createServer();
    t.after(() => closeServer(listener));
    const ready = once(listener, 'listening');
    listener.listen(reserved.port, '127.0.0.1');
    await ready;
  },
);

test(
  'TLS paths are read at listen and load failures close prior listeners',
  { timeout: 10000 },
  async (t) => {
    const cases = [
      null,
      { key: TLS_PATHS.key },
      { cert: TLS_PATHS.cert },
      { key: 'test/fixtures/missing-key.pem', cert: TLS_PATHS.cert },
      { key: TLS_PATHS.key, cert: 'test/fixtures/missing-cert.pem' },
      { key: TLS_PATHS.cert, cert: TLS_PATHS.cert },
    ];
    for (const paths of cases) {
      const reserved = await reserveTcp(t);
      await reserved.release();
      const { ice } = loadIce({
        port: 0,
        listen: '127.0.0.1',
        tlsPort: reserved.port,
        tls: paths,
      });
      t.after(() => ice.close());
      assert.equal(ice.listeners.length, 0);
      let port = 0;
      const bindTcp = ice.bindTcp.bind(ice);
      ice.bindTcp = async (effectivePort) => {
        port = effectivePort;
        await bindTcp(effectivePort);
      };
      await assert.rejects(ice.listen());
      assert.ok(port > 0);
      assert.deepEqual(ice.ports, { udp: 0, tcp: 0, tls: 0 });
      assert.equal(ice.listeners.length, 0);
      assert.equal(ice.connections.size, 0);
      await ice.close();
      const replacement = loadIce({ port }).ice;
      t.after(() => replacement.close());
      await replacement.listen();
      await replacement.close();
    }
    const { ice } = loadIce({ port: 0, tlsPort: 0, tls: cases[3] });
    t.after(() => ice.close());
    await ice.listen();
    assert.equal(ice.ports.tls, 0);
  },
);

test(
  'TLS bind failure waits for pending relay and connection cleanup',
  { timeout: 10000 },
  async (t) => {
    const occupied = await reserveTcp(t);
    const reservations = await reserveRange(t, 2);
    const { ice } = loadIce({
      ...turnOptions(),
      port: 0,
      listen: '127.0.0.1',
      tlsPort: occupied.port,
      tls: TLS_PATHS,
      relayPorts: reservations.range,
    });
    const binding = Promise.withResolvers();
    const failBind = Promise.withResolvers();
    const started = Promise.withResolvers();
    const opening = Promise.withResolvers();
    t.after(async () => {
      failBind.resolve();
      opening.resolve();
      await ice.close();
    });
    const bindTls = ice.bindTls.bind(ice);
    ice.bindTls = async (port) => {
      binding.resolve();
      await failBind.promise;
      return bindTls(port);
    };
    ice.openRelay = async (allocation) => {
      const relay = await allocation.openRelay();
      started.resolve();
      await opening.promise;
      return relay;
    };
    const rejected = assert.rejects(ice.listen(), { code: 'EADDRINUSE' });
    await binding.promise;
    const port = ice.ports.tcp;
    const client = await stream(t, port);
    await reservations.release();
    const auth = clientAuth(ice, 'pending-tls-bind');
    client.send(packet('allocate', [TRANSPORT], auth));
    await started.promise;
    const allocation = ice.allocations.values().next().value;
    const relayPort = allocation.port;
    failBind.resolve();
    await waitFor(() => ice.isClosing);
    assert.equal(ice.closingAllocations.size, 1);
    opening.resolve();
    await rejected;
    await ice.close();
    await client.closed;
    assert.equal(ice.allocations.size, 0);
    assert.equal(ice.relayPorts.size, 0);
    assert.equal(ice.connections.size, 0);
    assert.equal(ice.pendingRequests.size, 0);
    const relay = await reservePort(relayPort);
    await closeUdp(relay);
    const replacement = loadIce({ port }).ice;
    t.after(() => replacement.close());
    await replacement.listen();
    await replacement.close();
  },
);

const handshakeTitle =
  'TLS shutdown owns clients before their handshake completes';

test(handshakeTitle, async (t) => {
  const reserved = await reserveTcp(t);
  await reserved.release();
  const { ice } = loadIce({
    port: 0,
    listen: '127.0.0.1',
    tlsPort: reserved.port,
    tls: TLS_PATHS,
  });
  t.after(() => ice.close());
  await ice.listen();
  const client = await stream(t, ice.ports.tls);
  await waitFor(() => ice.handshakes.size === 1);
  const closing = ice.close();
  assert.equal(ice.close(), closing);
  await closing;
  await client.closed;
  assert.equal(ice.handshakes.size, 0);
  assert.equal(ice.closingConnections.size, 0);
  const replacement = loadIce({
    port: 0,
    listen: '127.0.0.1',
    tlsPort: reserved.port,
    tls: TLS_PATHS,
  }).ice;
  t.after(() => replacement.close());
  await replacement.listen();
  await replacement.close();
});
