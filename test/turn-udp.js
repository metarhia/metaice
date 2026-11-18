'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const dgram = require('node:dgram');
const { once } = require('node:events');

const helpers = require('./turn-helpers.js');
const { createNonce } = require('../lib/credentials.js');

const { loadIce, turnOptions, clientAuth, packet, codeOf, TRANSPORT } = helpers;

const closeUdp = (socket) =>
  new Promise((resolve, reject) => {
    try {
      socket.close(resolve);
    } catch (error) {
      if (error.code === 'ERR_SOCKET_DGRAM_NOT_RUNNING') resolve();
      else reject(error);
    }
  });

const reservePort = async (port) => {
  const socket = dgram.createSocket('udp4');
  try {
    const ready = once(socket, 'listening');
    socket.bind(port, '127.0.0.1');
    await ready;
    return socket;
  } catch (error) {
    await closeUdp(socket);
    throw error;
  }
};

const reserveRange = async (t, count) => {
  for (let attempt = 0; attempt < 100; attempt++) {
    const first = await reservePort(0);
    const port = first.address().port;
    const sockets = [first];
    const release = () => Promise.all(sockets.map(closeUdp));
    if (port + count > 65536) {
      await release();
      continue;
    }
    try {
      for (let i = 1; i < count; i++) {
        sockets.push(await reservePort(port + i));
      }
      t.after(release);
      return { sockets, release, range: [port, port + count - 1] };
    } catch (error) {
      await release();
      if (error.code !== 'EADDRINUSE') throw error;
    }
  }
  throw new Error('No contiguous UDP relay range available');
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

const fixture = async (t, allowPrivate = true, release = null) => {
  const reservations = await reserveRange(t, 4);
  const loaded = loadIce({
    ...turnOptions(allowPrivate),
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
  const client = await udp(t);
  const peer = await udp(t);
  const auth = clientAuth(ice, stun, 'socket-peer');
  const exchange = async (
    method,
    attributes,
    identity = auth,
    options = {},
  ) => {
    const buffer = packet(stun, method, attributes, identity, options);
    const reply = client.next();
    client.send(buffer, port);
    return reply;
  };
  const allocate = async () => {
    const reply = await exchange('allocate', [TRANSPORT]);
    assert.equal(codeOf(stun, reply), 0);
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

const requestPeer = (stun, port, attributes = []) => {
  const transactionId = crypto.randomBytes(12);
  const peer = helpers.peerAttribute(stun, transactionId, port);
  return { transactionId, attributes: attributes.concat([peer]) };
};

const channelNumber = (number) => {
  const value = Buffer.alloc(4);
  value.writeUInt16BE(number);
  return { type: 0x000c, value };
};

const channelPacket = (number, data) => {
  const buffer = Buffer.alloc(4 + data.length);
  buffer.writeUInt16BE(number, 0);
  buffer.writeUInt16BE(data.length, 2);
  data.copy(buffer, 4);
  return buffer;
};

const expectCode = (stun, reply, code, key) => {
  assert.equal(codeOf(stun, reply), code);
  const message = stun.decode(reply);
  assert.equal(stun.verifyFingerprint(reply, message), true);
  if (key) assert.equal(stun.verifyIntegrity(reply, message, key), true);
};

test(
  'TURN UDP socket lifecycle and protocol',
  { timeout: 45000 },
  async (t) => {
    await t.test(
      'one STUN listener handles challenge and allocation replay',
      async (t) => {
        const { ice, stun, client, auth, port, exchange } = await fixture(t);
        const binding = await exchange('binding', [], null);
        assert.equal(stun.decode(binding).kind, 'success');
        const challenge = await exchange('allocate', [TRANSPORT], null);
        expectCode(stun, challenge, 401);
        const nonce = stun
          .find(stun.decode(challenge), 0x0015)
          .value.toString();
        const identity = { ...auth, nonce };
        const transactionId = crypto.randomBytes(12);
        const success = await exchange('allocate', [TRANSPORT], identity, {
          transactionId,
        });
        expectCode(stun, success, 0, auth.key);
        const repeated = await exchange('allocate', [TRANSPORT], identity, {
          transactionId,
        });
        assert.equal(success.equals(repeated), true);
        expectCode(
          stun,
          await exchange('allocate', [TRANSPORT]),
          437,
          auth.key,
        );
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
        const send = requestPeer(stun, peer.port, [
          { type: 0x0013, value: Buffer.from('send') },
        ]);
        client.send(
          packet(stun, 'send', send.attributes, null, {
            transactionId: send.transactionId,
            kind: 'indication',
          }),
          port,
        );
        await assert.rejects(peer.next(100), /timeout/);
        const permission = requestPeer(stun, peer.port);
        expectCode(
          stun,
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
          packet(stun, 'send', send.attributes, null, {
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
        const binding = requestPeer(stun, peer.port, [channelNumber(0x4000)]);
        expectCode(
          stun,
          await exchange('channelBind', binding.attributes, auth, binding),
          0,
          auth.key,
        );
        const channelReply = peer.next();
        client.send(channelPacket(0x4000, Buffer.from('odd')), port);
        assert.equal((await channelReply).toString(), 'odd');
        const reverse = client.next();
        peer.send(Buffer.from('back!'), relay.port);
        const frame = await reverse;
        assert.equal(frame.readUInt16BE(0), 0x4000);
        assert.equal(frame.readUInt16BE(2), 5);
        assert.equal(frame.subarray(4).toString(), 'back!');
        const channelConflict = requestPeer(stun, secondPeer.port, [
          channelNumber(0x4000),
        ]);
        expectCode(
          stun,
          await exchange(
            'channelBind',
            channelConflict.attributes,
            auth,
            channelConflict,
          ),
          400,
          auth.key,
        );
        const peerConflict = requestPeer(stun, peer.port, [
          channelNumber(0x4001),
        ]);
        expectCode(
          stun,
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
        client.send(channelPacket(0x4000, Buffer.from('expired')), port);
        await assert.rejects(peer.next(100), /timeout/);
        peer.send(Buffer.from('expired'), relay.port);
        await assert.rejects(client.next(100), /timeout/);
        const rebound = requestPeer(stun, peer.port, [channelNumber(0x4000)]);
        expectCode(
          stun,
          await exchange('channelBind', rebound.attributes, auth, rebound),
          0,
          auth.key,
        );
        allocation.channels.get(0x4000).expires = Date.now() - 1;
        client.send(channelPacket(0x4000, Buffer.from('expired')), port);
        await assert.rejects(peer.next(100), /timeout/);
        allocation.tokens = 0;
        allocation.sampled = Date.now() + 10000;
        client.send(
          packet(stun, 'send', send.attributes, null, {
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
          stun,
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
        expectCode(stun, await exchange('refresh', []), 437, auth.key);
      },
    );

    await t.test(
      'authentication, private peers and required errors',
      async (t) => {
        const { ice, stun, auth, peer, exchange, allocate } = await fixture(
          t,
          false,
        );
        const wrong = { ...auth, key: crypto.randomBytes(16) };
        expectCode(stun, await exchange('allocate', [TRANSPORT], wrong), 401);
        const stale = {
          ...auth,
          nonce: createNonce(
            ice.options.secret,
            '127.0.0.1',
            Date.now() - 601000,
          ),
        };
        expectCode(
          stun,
          await exchange('allocate', [TRANSPORT], stale),
          438,
          auth.key,
        );
        await allocate();
        const permission = requestPeer(stun, peer.port);
        expectCode(
          stun,
          await exchange(
            'createPermission',
            permission.attributes,
            auth,
            permission,
          ),
          403,
          auth.key,
        );
        const identity = clientAuth(ice, stun, 'wrong-owner');
        expectCode(
          stun,
          await exchange('refresh', [], identity),
          441,
          identity.key,
        );
        expectCode(stun, await exchange('channelBind', []), 400, auth.key);
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
        const other = await udp(t);
        const request = packet(stun, 'allocate', [TRANSPORT], auth);
        const reply = other.next();
        other.send(request, port);
        expectCode(stun, await reply, 486, auth.key);
        const secondAuth = clientAuth(ice, stun, 'second-peer');
        const exhausted = other.next();
        other.send(packet(stun, 'allocate', [TRANSPORT], secondAuth), port);
        expectCode(stun, await exhausted, 508, secondAuth.key);
        const lifetime = Buffer.alloc(4);
        lifetime.writeUInt32BE(0xffffffff);
        const refreshed = await exchange('refresh', [
          { type: 0x000d, value: lifetime },
        ]);
        expectCode(stun, refreshed, 0, auth.key);
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
  'UDP pending replay shares a relay and drops collisions',
  { timeout: 10000 },
  async (t) => {
    const opening = Promise.withResolvers();
    const release = () => opening.resolve();
    const f = await fixture(t, true, release);
    const { ice, stun, client, auth, port } = f;
    const started = Promise.withResolvers();
    const arrived = Promise.withResolvers();
    let binds = 0;
    let received = 0;
    const listener = ice.listeners.find((item) => item.transport === 'udp4');
    const onMessage = () => {
      received++;
      if (received === 3) arrived.resolve();
    };
    listener.socket.on('message', onMessage);
    t.after(() => listener.socket.off('message', onMessage));
    ice.openRelay = async (allocation) => {
      binds++;
      started.resolve();
      await opening.promise;
      return allocation.openRelay();
    };
    const transactionId = crypto.randomBytes(12);
    const request = packet(stun, 'allocate', [TRANSPORT], auth, {
      transactionId,
    });
    client.send(request, port);
    await started.promise;
    client.send(request, port);
    const collision = packet(stun, 'allocate', [], auth, { transactionId });
    client.send(collision, port);
    await arrived.promise;
    assert.equal(binds, 1);
    assert.equal(ice.allocations.size, 1);
    opening.resolve();
    const first = await client.next();
    const repeated = await client.next();
    expectCode(stun, first, 0, auth.key);
    assert.deepEqual(repeated, first);
    await assert.rejects(client.next(100), /timeout/);
  },
);

test(
  'UDP integrity tails cannot allocate, permit or delete',
  { timeout: 10000 },
  async (t) => {
    const { ice, stun, client, auth, port, exchange, allocate } =
      await fixture(t);
    const signed = packet(stun, 'allocate', [], auth);
    const decoded = stun.decode(signed);
    const integrity = stun.find(decoded, 0x0008);
    const tail = stun.attribute(TRANSPORT.type, TRANSPORT.value);
    const forged = Buffer.concat([
      signed.subarray(0, integrity.offset + 24),
      tail,
    ]);
    forged.writeUInt16BE(forged.length - 20, 2);
    client.send(forged, port);
    expectCode(stun, await client.next(), 400, auth.key);
    assert.equal(ice.allocations.size, 0);
    await allocate();
    const transactionId = crypto.randomBytes(12);
    const peer = helpers.peerAttribute(stun, transactionId, client.port);
    const request = packet(stun, 'createPermission', [], auth, {
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
    expectCode(stun, await client.next(), 400, auth.key);
    const allocation = ice.allocations.values().next().value;
    assert.equal(allocation.permissions.size, 0);
    const wrong = { ...auth, key: crypto.randomBytes(16) };
    const lifetime = { type: 0x000d, value: Buffer.alloc(4) };
    expectCode(stun, await exchange('refresh', [lifetime], wrong), 401);
    assert.equal(ice.allocations.size, 1);
  },
);

test(
  'UDP permission validation is atomic and blocks mapped peers',
  { timeout: 10000 },
  async (t) => {
    const { ice, stun, auth, exchange, allocate, peer } = await fixture(
      t,
      false,
    );
    await allocate();
    const transactionId = crypto.randomBytes(12);
    const allowed = helpers.peerAttribute(
      stun,
      transactionId,
      peer.port,
      '198.51.100.1',
    );
    const blocked = helpers.peerAttribute(stun, transactionId, peer.port);
    expectCode(
      stun,
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
      stun,
      allowedId,
      peer.port,
      '198.51.100.1',
    );
    expectCode(
      stun,
      await exchange('createPermission', [publicPeer], auth, {
        transactionId: allowedId,
      }),
      0,
      auth.key,
    );
    assert.equal(allocation.permissions.size, 1);
    const mappedId = crypto.randomBytes(12);
    const mapped = helpers.peerAttribute(
      stun,
      mappedId,
      peer.port,
      '::ffff:808:808',
    );
    expectCode(
      stun,
      await exchange('createPermission', [mapped], auth, {
        transactionId: mappedId,
      }),
      403,
      auth.key,
    );
    const ipv6Id = crypto.randomBytes(12);
    const ipv6 = helpers.peerAttribute(stun, ipv6Id, peer.port, '2001:db8::1');
    expectCode(
      stun,
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
  'UDP close awaits an opening relay and releases its port',
  { timeout: 10000 },
  async (t) => {
    const started = Promise.withResolvers();
    const opening = Promise.withResolvers();
    const release = () => opening.resolve();
    const f = await fixture(t, true, release);
    const { ice, stun, client, auth, port, config } = f;
    ice.openRelay = async (allocation) => {
      const relay = await allocation.openRelay();
      started.resolve();
      await opening.promise;
      return relay;
    };
    client.send(packet(stun, 'allocate', [TRANSPORT], auth), port);
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
    await assert.rejects(client.next(100), /timeout/);
  },
);

test(
  'listener failure waits for pending TURN relay cleanup',
  { timeout: 10000 },
  async (t) => {
    const reservations = await reserveRange(t, 2);
    const { ice, stun } = loadIce({
      ...turnOptions(),
      port: 0,
      listen: '127.0.0.1',
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
    ice.bindTcp = async () => {
      binding.resolve();
      await failBind.promise;
      throw new Error('selected listener failure');
    };
    ice.openRelay = async (allocation) => {
      const relay = await allocation.openRelay();
      started.resolve();
      await opening.promise;
      return relay;
    };
    const rejected = assert.rejects(ice.listen(), /selected listener failure/);
    await binding.promise;
    const port = ice.ports.udp;
    const client = await udp(t);
    await reservations.release();
    const auth = clientAuth(ice, stun, 'pending-bind');
    client.send(packet(stun, 'allocate', [TRANSPORT], auth), port);
    await started.promise;
    const allocation = ice.allocations.values().next().value;
    const relayPort = allocation.port;
    failBind.resolve();
    await new Promise((resolve) => {
      setImmediate(resolve);
    });
    assert.equal(ice.isClosing, true);
    assert.equal(ice.closingAllocations.size, 1);
    opening.resolve();
    await rejected;
    await ice.close();
    assert.equal(ice.allocations.size, 0);
    assert.equal(ice.relayPorts.size, 0);
    assert.equal(ice.pendingRequests.size, 0);
    const relay = await reservePort(relayPort);
    await closeUdp(relay);
    const replacement = loadIce({ port }).ice;
    t.after(() => replacement.close());
    await replacement.listen();
    await replacement.close();
  },
);
