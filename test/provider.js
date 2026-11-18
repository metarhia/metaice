'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const dgram = require('node:dgram');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const net = require('node:net');
const path = require('node:path');
const { test } = require('node:test');
const { setTimeout: delay } = require('node:timers/promises');
const tls = require('node:tls');

const { protocols, stun } = require('../metaice.js');
const { relaySlice, start } = require('../lib/service.js');
const helpers = require('./turn-helpers.js');

const { turnOptions, clientAuth, packet, codeOf, peerAttribute, TRANSPORT } =
  helpers;

const SLICE_ERROR = 'Invalid relay thread or port range';
const TLS_KEY = path.join(__dirname, 'fixtures/turn-key.pem');
const TLS_CERT = path.join(__dirname, 'fixtures/turn-cert.pem');

const createLogger = (logs) => ({
  log: (value) => logs.push(value),
  info: (value) => logs.push(value),
  warn: (value) => logs.push(value),
  debug: (value) => logs.push(value),
  error: (value) => logs.push(value),
});

const closeUdp = (socket) =>
  new Promise((resolve, reject) => {
    try {
      socket.close((error) => {
        const closed = error?.code === 'ERR_SOCKET_DGRAM_NOT_RUNNING';
        if (error && !closed) reject(error);
        else resolve();
      });
    } catch (error) {
      if (error.code === 'ERR_SOCKET_DGRAM_NOT_RUNNING') resolve();
      else reject(error);
    }
  });

const reservePort = (port) =>
  new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      closeUdp(socket).then(
        () => reject(error),
        () => reject(error),
      );
    };
    socket.once('error', fail);
    socket.once('listening', () => {
      if (settled) return;
      settled = true;
      socket.off('error', fail);
      socket.on('error', (error) => {
        throw error;
      });
      resolve(socket);
    });
    try {
      socket.bind(port, '127.0.0.1');
    } catch (error) {
      fail(error);
    }
  });

const reserveRange = async (t, count) => {
  for (let attempt = 0; attempt < 100; attempt++) {
    const first = await reservePort(0);
    const port = first.address().port;
    const sockets = [first];
    const releaseOne = (socket) => closeUdp(socket);
    const release = () => Promise.all(sockets.map(releaseOne));
    if (port + count > 65536) {
      await release();
      continue;
    }
    try {
      for (let i = 1; i < count; i++) {
        sockets.push(await reservePort(port + i));
      }
      t.after(release);
      return { release, range: [port, port + count - 1] };
    } catch (error) {
      await release();
      if (error.code !== 'EADDRINUSE') throw error;
    }
  }
  throw new Error('No contiguous UDP relay range available');
};

const reserveExact = async (ports) => {
  const sockets = [];
  try {
    for (let i = 0; i < ports.length; i++) {
      sockets.push(await reservePort(ports[i]));
    }
    return sockets;
  } catch (error) {
    await Promise.all(sockets.map((socket) => closeUdp(socket)));
    throw error;
  }
};

const findHalves = async (t) => {
  const hint = await reservePort(0);
  const hintPort = hint.address().port;
  await closeUdp(hint);
  for (let attempt = 0; attempt < 40; attempt++) {
    const startPort = hintPort + attempt;
    if (startPort + 199 > 65535) break;
    try {
      const sockets = await reserveExact([startPort, startPort + 100]);
      const release = () =>
        Promise.all(sockets.map((socket) => closeUdp(socket)));
      t.after(release);
      return { sockets, release, range: [startPort, startPort + 199] };
    } catch (error) {
      if (error.code !== 'EADDRINUSE') throw error;
    }
  }
  throw new Error('No 200-port relay window available');
};

const threadContext = (logs, index, count, protocols) => {
  const context = {
    console: createLogger(logs),
    mode: 'test',
    thread: { group: 'ice', index, count },
  };
  if (protocols) context.protocols = protocols;
  return context;
};

const providerOptions = (relayPorts, extra = {}) => ({
  ...turnOptions(),
  listen: '127.0.0.1',
  port: 0,
  relayPorts,
  ...extra,
});

const authFor = (options, peer) => {
  const ice = {
    options: {
      realm: 'metaice',
      credentialTtl: 86400,
      secret: options.secret,
    },
  };
  return clientAuth(ice, stun, peer, '127.0.0.1');
};

const channelNumber = (number) => {
  const value = Buffer.alloc(4);
  value.writeUInt16BE(number, 0);
  return { type: 0x000c, value };
};

const channelPacket = (number, data) => {
  const padded = Math.ceil(data.length / 4) * 4;
  const buffer = Buffer.alloc(4 + padded);
  buffer.writeUInt16BE(number, 0);
  buffer.writeUInt16BE(data.length, 2);
  data.copy(buffer, 4);
  return buffer;
};

const openFrames = (socket) => {
  const queue = [];
  let pending = null;
  let buffer = Buffer.alloc(0);
  const take = (frame) => {
    if (!pending) {
      queue.push(frame);
      return;
    }
    const current = pending;
    pending = null;
    clearTimeout(current.timer);
    current.resolve(frame);
  };
  socket.on('data', (chunk) => {
    buffer = buffer.length > 0 ? Buffer.concat([buffer, chunk]) : chunk;
    while (buffer.length >= 4) {
      const isChannel = buffer[0] >= 0x40 && buffer[0] <= 0x4f;
      const size = buffer.readUInt16BE(2);
      const length = isChannel ? 4 + Math.ceil(size / 4) * 4 : 20 + size;
      if (buffer.length < length) return;
      const frame = Buffer.from(buffer.subarray(0, length));
      buffer = buffer.subarray(length);
      take(frame);
    }
  });
  socket.on('error', (error) => {
    if (!pending) return;
    const current = pending;
    pending = null;
    clearTimeout(current.timer);
    current.reject(error);
  });
  const next = (timeoutMs = 2000) => {
    if (queue.length > 0) return Promise.resolve(queue.shift());
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending = null;
        reject(new Error('stream response timeout'));
      }, timeoutMs);
      pending = { resolve, reject, timer };
    });
  };
  return { next };
};

const openUdp = async (t) => {
  const socket = dgram.createSocket('udp4');
  const queue = [];
  let pending = null;
  socket.on('message', (buffer) => {
    const copy = Buffer.from(buffer);
    if (!pending) {
      queue.push(copy);
      return;
    }
    const current = pending;
    pending = null;
    clearTimeout(current.timer);
    current.resolve(copy);
  });
  socket.on('error', (error) => {
    if (!pending) throw error;
    const current = pending;
    pending = null;
    clearTimeout(current.timer);
    current.reject(error);
  });
  t.after(() => closeUdp(socket));
  const ready = once(socket, 'listening');
  socket.bind(0, '127.0.0.1');
  await ready;
  const next = (timeoutMs = 2000) => {
    if (queue.length > 0) return Promise.resolve(queue.shift());
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending = null;
        reject(new Error('UDP response timeout'));
      }, timeoutMs);
      pending = { resolve, reject, timer };
    });
  };
  const remote = () => {
    const address = socket.address();
    return {
      address: address.address,
      port: address.port,
      family: address.family,
    };
  };
  const send = (buffer, port) => {
    socket.send(buffer, port, '127.0.0.1');
  };
  return { socket, next, remote, send, port: socket.address().port };
};

const connectionInfo = (socket, tlsOn) => ({
  port: socket.localPort,
  transport: 'tcp',
  tls: tlsOn,
  servername: socket.servername ?? '',
  alpn: socket.alpnProtocol ?? '',
  remote: {
    address: socket.remoteAddress,
    port: socket.remotePort,
    family: socket.remoteFamily,
  },
});

const openTcp = async (t) => {
  const listener = net.createServer();
  await new Promise((resolve) => {
    listener.listen(0, '127.0.0.1', resolve);
  });
  const acceptedPromise = new Promise((resolve) => {
    listener.once('connection', (socket) => {
      socket.pause();
      resolve(socket);
    });
  });
  const port = listener.address().port;
  const client = net.connect({ port, host: '127.0.0.1' });
  let accepted = null;
  t.after(() => {
    client.destroy();
    if (accepted) accepted.destroy();
    listener.close();
  });
  client.setNoDelay(true);
  const connected = once(client, 'connect');
  accepted = await acceptedPromise;
  await connected;
  const frames = openFrames(client);
  return { client, accepted, next: frames.next, port: client.localPort };
};

const openTls = async (t) => {
  const key = await fs.readFile(TLS_KEY);
  const cert = await fs.readFile(TLS_CERT);
  const listener = tls.createServer({ key, cert });
  await new Promise((resolve) => {
    listener.listen(0, '127.0.0.1', resolve);
  });
  const acceptedPromise = new Promise((resolve) => {
    listener.once('secureConnection', (socket) => {
      socket.pause();
      resolve(socket);
    });
  });
  const port = listener.address().port;
  const client = tls.connect({
    port,
    host: '127.0.0.1',
    rejectUnauthorized: false,
  });
  let accepted = null;
  t.after(() => {
    client.destroy();
    if (accepted) accepted.destroy();
    listener.close();
  });
  client.setNoDelay(true);
  const connected = once(client, 'secureConnect');
  accepted = await acceptedPromise;
  await connected;
  const frames = openFrames(client);
  return { client, accepted, next: frames.next, port: client.localPort };
};

const assertHandler = (handle) => {
  assert.deepEqual(Object.keys(handle), ['connection', 'datagram', 'stop']);
};

const assertNoListen = (logs) => {
  const listed = logs.some((entry) => entry && typeof entry.tcp === 'number');
  assert.equal(listed, false);
};

const sendRequest = (link, method, attributes, auth, options) => {
  const reply = link.next();
  link.deliver(packet(stun, method, attributes, auth, options));
  return reply;
};

const assertBinding = (buffer, port) => {
  const message = stun.decode(buffer);
  assert.equal(message.kind, 'success');
  assert.equal(message.method, stun.METHODS.binding);
  assert.equal(stun.verifyFingerprint(buffer, message), true);
  const value = stun.find(message, stun.ATTRIBUTES.xorMappedAddress).value;
  const mapped = stun.readAddress(value, message.transactionId);
  assert.equal(mapped.address, '127.0.0.1');
  assert.equal(mapped.port, port);
};

const assertAllocated = (buffer, key) => {
  assert.equal(codeOf(stun, buffer), 0);
  const message = stun.decode(buffer);
  assert.equal(stun.verifyIntegrity(buffer, message, key), true);
  assert.equal(stun.verifyFingerprint(buffer, message), true);
  const value = stun.find(message, stun.ATTRIBUTES.xorRelayedAddress).value;
  return stun.readAddress(value, message.transactionId);
};

const proveTurn = async (link) => {
  const binding = await sendRequest(link, 'binding', [], null);
  assertBinding(binding, link.localPort);
  const challenge = await sendRequest(link, 'allocate', [TRANSPORT], null);
  assert.equal(codeOf(stun, challenge), 401);
  const nonce = stun.find(stun.decode(challenge), 0x0015).value.toString();
  const identity = { ...link.auth, nonce };
  const success = await sendRequest(link, 'allocate', [TRANSPORT], identity);
  const relay = assertAllocated(success, link.auth.key);
  assert.equal(relay.address, '127.0.0.1');
  const transactionId = crypto.randomBytes(12);
  const peer = peerAttribute(stun, transactionId, link.peer.port);
  const attributes = [channelNumber(0x4000), peer];
  const bound = await sendRequest(link, 'channelBind', attributes, identity, {
    transactionId,
  });
  assert.equal(codeOf(stun, bound), 0);
  const boundMessage = stun.decode(bound);
  const intact = stun.verifyIntegrity(bound, boundMessage, identity.key);
  assert.equal(intact, true);
  const outbound = link.peer.next();
  link.deliver(channelPacket(0x4000, Buffer.from('odd')));
  assert.equal((await outbound).toString(), 'odd');
  const inbound = link.next();
  link.peer.send(Buffer.from('five!'), relay.port);
  const frame = await inbound;
  assert.equal(frame.readUInt16BE(0), 0x4000);
  assert.equal(frame.readUInt16BE(2), 5);
  assert.equal(frame.subarray(4, 9).toString(), 'five!');
  if (link.padded) {
    assert.equal(frame.length, 12);
    assert.deepEqual(frame.subarray(9), Buffer.alloc(3));
  }
  const label = `client=${link.label}`;
  const logged = link.logs.some((line) => String(line).includes(label));
  assert.equal(logged, true);
  assertNoListen(link.logs);
  return relay;
};

const waitUntilFree = async (port) => {
  const deadline = Date.now() + 4000;
  let failure = new Error('Relay port stayed busy');
  while (Date.now() < deadline) {
    try {
      const socket = await reservePort(port);
      await closeUdp(socket);
      return;
    } catch (error) {
      failure = error;
      if (error.code !== 'EADDRINUSE') throw error;
      await delay(50);
    }
  }
  throw failure;
};

test('protocols match package.json', () => {
  const pkg = require('../package.json');
  assert.deepEqual(pkg.metarhia.protocols, protocols);
  assert.deepEqual(protocols, ['stun.turn', 'stun.nat-discovery']);
});

test('relay slices follow index and count', () => {
  const range = [49160, 49359];
  const left = relaySlice(range, 0, 2);
  const right = relaySlice(range, 1, 2);
  const first = relaySlice(range, 0, 3);
  const middle = relaySlice(range, 1, 3);
  const last = relaySlice(range, 2, 3);
  const low = relaySlice([1000, 1004], 0, 2);
  const high = relaySlice([1000, 1004], 1, 2);
  assert.deepEqual(left, [49160, 49259]);
  assert.deepEqual(right, [49260, 49359]);
  assert.deepEqual(relaySlice(undefined, 0, 2), left);
  assert.deepEqual(relaySlice(undefined, 1, 2), right);
  assert.deepEqual(first, [49160, 49226]);
  assert.deepEqual(middle, [49227, 49293]);
  assert.deepEqual(last, [49294, 49359]);
  assert.equal(first[1] - first[0] + 1, 67);
  assert.equal(last[1] - last[0] + 1, 66);
  assert.deepEqual(low, [1000, 1002]);
  assert.deepEqual(high, [1003, 1004]);
  assert.throws(() => relaySlice(range, 0, 201), { message: SLICE_ERROR });
  assert.throws(() => relaySlice(range, -1, 2), { message: SLICE_ERROR });
  assert.throws(() => relaySlice(range, 2, 2), { message: SLICE_ERROR });
  assert.throws(() => relaySlice([1000, 1004], 0, 0), { message: SLICE_ERROR });
});

test('provider refuses a thread count above the relay range', async () => {
  const relayPorts = [49160, 49359];
  const options = { relayPorts, secret: 'kept' };
  const context = (index, count) => ({
    thread: { group: 'ice', index, count },
  });
  await assert.rejects(start(options, context(0, 201)), {
    message: SLICE_ERROR,
  });
  await assert.rejects(start(options, context(2, 2)), { message: SLICE_ERROR });
  await assert.rejects(start(options, context(0, 0)), { message: SLICE_ERROR });
  await assert.rejects(start(options, context(-1, 1)), {
    message: SLICE_ERROR,
  });
  await assert.rejects(start({}, context(0, 201)), { message: SLICE_ERROR });
  await assert.rejects(start(options, { thread: 1 }), { message: SLICE_ERROR });
  assert.equal(options.secret, 'kept');
  assert.deepEqual(options.relayPorts, [49160, 49359]);
  assert.equal(options.relayPorts, relayPorts);
});

test(
  'TCP provider answers buffered Binding, Allocate, and ChannelData',
  { timeout: 10000 },
  async (t) => {
    const reserved = await reserveRange(t, 2);
    const logs = [];
    const options = providerOptions(reserved.range);
    const handle = await start(options, threadContext(logs, 0, 1));
    t.after(() => handle.stop());
    assertHandler(handle);
    await reserved.release();
    const pair = await openTcp(t);
    const peer = await openUdp(t);
    const request = packet(stun, 'binding', [], null);
    const readable = once(pair.accepted, 'readable');
    pair.client.write(request);
    await readable;
    assert.ok(pair.accepted.readableLength > 0);
    const early = pair.next();
    handle.connection(pair.accepted, connectionInfo(pair.accepted, false));
    assertBinding(await early, pair.port);
    const link = {
      deliver: (buffer) => pair.client.write(buffer),
      next: pair.next,
      localPort: pair.port,
      auth: authFor(options, 'tcp-peer'),
      peer,
      logs,
      label: 'tcp',
      padded: true,
    };
    const relay = await proveTurn(link);
    assert.equal(relay.port, reserved.range[0]);
  },
);

test(
  'TLS provider answers Binding, Allocate, and ChannelData',
  { timeout: 10000 },
  async (t) => {
    const reserved = await reserveRange(t, 2);
    const logs = [];
    const options = providerOptions(reserved.range);
    const handle = await start(options, threadContext(logs, 0, 1));
    t.after(() => handle.stop());
    assertHandler(handle);
    await reserved.release();
    const pair = await openTls(t);
    const peer = await openUdp(t);
    handle.connection(pair.accepted, connectionInfo(pair.accepted, true));
    const link = {
      deliver: (buffer) => pair.client.write(buffer),
      next: pair.next,
      localPort: pair.port,
      auth: authFor(options, 'tls-peer'),
      peer,
      logs,
      label: 'tls',
      padded: true,
    };
    const relay = await proveTurn(link);
    assert.equal(relay.port, reserved.range[0]);
  },
);

test(
  'UDP provider answers Binding, Allocate, and ChannelData',
  { timeout: 10000 },
  async (t) => {
    const reserved = await reserveRange(t, 2);
    const logs = [];
    const enabled = ['stun.turn', 'stun.nat-discovery'];
    const options = providerOptions(reserved.range);
    const handle = await start(options, threadContext(logs, 0, 1, enabled));
    t.after(() => handle.stop());
    assertHandler(handle);
    await reserved.release();
    const impress = await openUdp(t);
    const client = await openUdp(t);
    const peer = await openUdp(t);
    const remote = {
      address: client.remote().address,
      port: client.remote().port,
    };
    const link = {
      deliver: (buffer) => handle.datagram(buffer, remote, impress.socket),
      next: client.next,
      localPort: client.port,
      auth: authFor(options, 'udp-peer'),
      peer,
      logs,
      label: 'udp',
      padded: false,
    };
    const relay = await proveTurn(link);
    assert.equal(relay.port, reserved.range[0]);
    assert.equal(remote.family, undefined);
  },
);

test(
  'provider relay ports are sliced across threads',
  { timeout: 15000 },
  async (t) => {
    const halves = await findHalves(t);
    const leftSocket = halves.sockets[0];
    const rightSocket = halves.sockets[1];
    await closeUdp(leftSocket);
    const logs = [];
    const options = providerOptions(halves.range);
    const secret = options.secret;
    const left = await start(options, threadContext(logs, 0, 2));
    t.after(() => left.stop());
    assertHandler(left);
    const impress = await openUdp(t);
    const client = await openUdp(t);
    const remote = client.remote();
    const deliver = (buffer) => left.datagram(buffer, remote, impress.socket);
    const link = { deliver, next: client.next };
    const auth = authFor(options, 'slice-peer');
    const success = await sendRequest(link, 'allocate', [TRANSPORT], auth);
    const relay = assertAllocated(success, auth.key);
    assert.equal(relay.port, halves.range[0]);
    assert.deepEqual(relaySlice(halves.range, 0, 2), [
      halves.range[0],
      halves.range[0] + 99,
    ]);
    await left.stop();
    await closeUdp(rightSocket);
    const rightLogs = [];
    const right = await start(options, threadContext(rightLogs, 1, 2));
    t.after(() => right.stop());
    const other = await openUdp(t);
    const rightLink = {
      deliver: (buffer) => {
        right.datagram(buffer, other.remote(), impress.socket);
      },
      next: other.next,
    };
    const opened = await sendRequest(rightLink, 'allocate', [TRANSPORT], auth);
    const second = assertAllocated(opened, auth.key);
    assert.equal(second.port, halves.range[0] + 100);
    assert.deepEqual(relaySlice(halves.range, 1, 2), [
      halves.range[0] + 100,
      halves.range[0] + 199,
    ]);
    assert.equal(options.secret, secret);
    assert.deepEqual(options.relayPorts, halves.range);
    await right.stop();

    const uneven = await reserveRange(t, 5);
    const unevenOptions = providerOptions(uneven.range);
    await uneven.release();
    const lowLogs = [];
    const low = await start(unevenOptions, threadContext(lowLogs, 0, 2));
    t.after(() => low.stop());
    const lowAuth = authFor(unevenOptions, 'extra-peer');
    const ports = [];
    for (let i = 0; i < 3; i++) {
      const endpoint = await openUdp(t);
      const lowLink = {
        deliver: (buffer) => {
          low.datagram(buffer, endpoint.remote(), impress.socket);
        },
        next: endpoint.next,
      };
      const reply = await sendRequest(
        lowLink,
        'allocate',
        [TRANSPORT],
        lowAuth,
      );
      const allocated = assertAllocated(reply, lowAuth.key);
      ports.push(allocated.port);
    }
    assert.deepEqual(ports, [
      uneven.range[0],
      uneven.range[0] + 1,
      uneven.range[0] + 2,
    ]);
    const overflow = await openUdp(t);
    const overflowLink = {
      deliver: (buffer) => {
        low.datagram(buffer, overflow.remote(), impress.socket);
      },
      next: overflow.next,
    };
    const denied = await sendRequest(
      overflowLink,
      'allocate',
      [TRANSPORT],
      lowAuth,
    );
    assert.equal(codeOf(stun, denied), 508);
    await low.stop();
    const highLogs = [];
    const high = await start(unevenOptions, threadContext(highLogs, 1, 2));
    t.after(() => high.stop());
    const highClient = await openUdp(t);
    const highLink = {
      deliver: (buffer) => {
        high.datagram(buffer, highClient.remote(), impress.socket);
      },
      next: highClient.next,
    };
    const highAuth = authFor(unevenOptions, 'high-peer');
    const highReply = await sendRequest(
      highLink,
      'allocate',
      [TRANSPORT],
      highAuth,
    );
    const highRelay = assertAllocated(highReply, highAuth.key);
    assert.equal(highRelay.port, uneven.range[0] + 3);
    await high.stop();
  },
);

test(
  'protocols without stun.turn answer Binding only',
  { timeout: 10000 },
  async (t) => {
    const reserved = await reserveRange(t, 1);
    const logs = [];
    const options = providerOptions(reserved.range);
    const secret = options.secret;
    const handle = await start(
      options,
      threadContext(logs, 0, 1, ['stun.nat-discovery']),
    );
    t.after(() => handle.stop());
    assertHandler(handle);
    await reserved.release();
    const pair = await openTcp(t);
    handle.connection(pair.accepted, connectionInfo(pair.accepted, false));
    const link = {
      deliver: (buffer) => pair.client.write(buffer),
      next: pair.next,
      localPort: pair.port,
    };
    const binding = await sendRequest(link, 'binding', [], null);
    assertBinding(binding, pair.port);
    const allocate = packet(stun, 'allocate', [TRANSPORT], null);
    const pending = pair.next(200);
    pair.client.write(allocate);
    await assert.rejects(pending, /stream response timeout/);
    assert.equal(options.secret, secret);
    assertNoListen(logs);
    await handle.stop();
    await handle.stop();
  },
);

test(
  'stop closes relays and a second stop is safe',
  { timeout: 10000 },
  async (t) => {
    const reserved = await reserveRange(t, 1);
    const logs = [];
    const options = providerOptions(reserved.range);
    const handle = await start(options, threadContext(logs, 0, 1));
    t.after(() => handle.stop());
    await reserved.release();
    const impress = await openUdp(t);
    const client = await openUdp(t);
    const link = {
      deliver: (buffer) => {
        handle.datagram(buffer, client.remote(), impress.socket);
      },
      next: client.next,
    };
    const auth = authFor(options, 'stop-peer');
    const success = await sendRequest(link, 'allocate', [TRANSPORT], auth);
    const relay = assertAllocated(success, auth.key);
    const pair = await openTcp(t);
    handle.connection(pair.accepted, connectionInfo(pair.accepted, false));
    const acceptedClosed = once(pair.accepted, 'close');
    await assert.rejects(reservePort(relay.port), { code: 'EADDRINUSE' });
    const impressPort = impress.socket.address().port;
    await handle.stop();
    const again = handle.stop();
    assert.equal(typeof again.then, 'function');
    await again;
    await acceptedClosed;
    const reused = await reservePort(relay.port);
    await closeUdp(reused);
    assert.equal(impress.socket.address().port, impressPort);
  },
);

test(
  'provider sweep closes an expired relay',
  { timeout: 10000 },
  async (t) => {
    const reserved = await reserveRange(t, 1);
    const logs = [];
    const options = providerOptions(reserved.range, {
      allocationLifetime: [1, 1],
    });
    const handle = await start(options, threadContext(logs, 0, 1));
    t.after(() => handle.stop());
    await reserved.release();
    const impress = await openUdp(t);
    const client = await openUdp(t);
    const link = {
      deliver: (buffer) => {
        handle.datagram(buffer, client.remote(), impress.socket);
      },
      next: client.next,
    };
    const auth = authFor(options, 'sweep-peer');
    const success = await sendRequest(link, 'allocate', [TRANSPORT], auth);
    const relay = assertAllocated(success, auth.key);
    await assert.rejects(reservePort(relay.port), { code: 'EADDRINUSE' });
    await waitUntilFree(relay.port);
    await handle.stop();
  },
);
