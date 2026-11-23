'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const dgram = require('node:dgram');
const { once } = require('node:events');
const net = require('node:net');
const { test } = require('node:test');
const { setTimeout: delay } = require('node:timers/promises');

const { stun, IceServer } = require('../metaice.js');

const TIMEOUT_MS = 2000;
const IPV6_CODES = ['EAFNOSUPPORT', 'EADDRNOTAVAIL', 'EPROTONOSUPPORT'];

const closeUdp = (socket) =>
  new Promise((resolve, reject) => {
    try {
      socket.close(resolve);
    } catch (error) {
      if (error.code === 'ERR_SOCKET_DGRAM_NOT_RUNNING') resolve();
      else reject(error);
    }
  });

const createUdp = (t, type = 'udp4') => {
  const socket = dgram.createSocket({ type, ipv6Only: type === 'udp6' });
  t.after(() => closeUdp(socket));
  return socket;
};

const bindUdp = async (socket, port = 0, address = '127.0.0.1') => {
  const ready = once(socket, 'listening');
  socket.bind(port, address);
  await ready;
};

const supportsIpv6 = async (t) => {
  const socket = createUdp(t, 'udp6');
  try {
    await bindUdp(socket, 0, '::');
    return true;
  } catch (error) {
    if (IPV6_CODES.includes(error.code)) return false;
    throw error;
  } finally {
    await closeUdp(socket);
  }
};

const request = (attributes = [], kind = 'request') => {
  const type = stun.typeOf(stun.METHODS.binding, kind);
  const transactionId = crypto.randomBytes(12);
  return stun.encode({ type, transactionId, attributes, fingerprint: true });
};

const exchangeUdp = (socket, port, packet, address = '127.0.0.1') =>
  new Promise((resolve, reject) => {
    let cleanup = null;
    const onMessage = (buffer) => {
      cleanup();
      resolve(buffer);
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const timer = setTimeout(() => {
      onError(new Error('No STUN reply'));
    }, TIMEOUT_MS);
    cleanup = () => {
      clearTimeout(timer);
      socket.off('message', onMessage);
      socket.off('error', onError);
    };
    socket.once('message', onMessage);
    socket.once('error', onError);
    socket.send(packet, port, address, (error) => {
      if (error) onError(error);
    });
  });

const checkResponse = (buffer, packet, local, software = 'metaice') => {
  const message = stun.decode(buffer);
  assert.ok(message);
  assert.strictEqual(message.kind, 'success');
  assert.strictEqual(message.method, stun.METHODS.binding);
  assert.deepStrictEqual(message.transactionId, packet.subarray(8, 20));
  assert.ok(stun.verifyFingerprint(buffer, message));
  const attribute = stun.find(message, stun.ATTRIBUTES.xorMappedAddress);
  const mapped = stun.readAddress(attribute.value, message.transactionId);
  assert.strictEqual(mapped.family, local.family);
  assert.strictEqual(mapped.port, local.port);
  if (local.family === 'IPv4') {
    assert.strictEqual(mapped.address, local.address);
  } else {
    assert.deepStrictEqual(
      stun.parseV6(mapped.address),
      stun.parseV6(local.address),
    );
  }
  const name = stun.find(message, stun.ATTRIBUTES.software);
  assert.strictEqual(name.value.toString(), software);
};

const checkUnknownResponse = (buffer, packet) => {
  const message = stun.decode(buffer);
  assert.ok(message);
  assert.strictEqual(message.method, stun.METHODS.binding);
  assert.strictEqual(message.kind, 'error');
  assert.deepStrictEqual(message.transactionId, packet.subarray(8, 20));
  assert.ok(stun.verifyFingerprint(buffer, message));
  const error = stun.find(message, stun.ATTRIBUTES.errorCode);
  assert.strictEqual(error.value[2] * 100 + error.value[3], 420);
  const unknown = stun.find(message, stun.ATTRIBUTES.unknownAttributes);
  assert.deepStrictEqual(unknown.value, Buffer.from([0, 2, 0, 4]));
};

const closeTcp = async (socket) => {
  if (socket.closed) return;
  const closed = once(socket, 'close');
  socket.destroy();
  await closed;
};

const connect = async (t, port) => {
  const socket = net.createConnection({ port, host: '127.0.0.1' });
  t.after(() => closeTcp(socket));
  await once(socket, 'connect');
  socket.setNoDelay(true);
  return socket;
};

const readTcp = (socket, count) =>
  new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let cleanup = null;
    const packets = [];
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onClose = () => onError(new Error('TCP closed before STUN reply'));
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= stun.HEADER_SIZE) {
        const length = stun.HEADER_SIZE + buffer.readUInt16BE(2);
        if (buffer.length < length) return;
        packets.push(buffer.subarray(0, length));
        buffer = buffer.subarray(length);
        if (packets.length === count) {
          cleanup();
          resolve(packets);
          return;
        }
      }
    };
    const timer = setTimeout(() => {
      onError(new Error('No TCP STUN reply'));
    }, TIMEOUT_MS);
    cleanup = () => {
      clearTimeout(timer);
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
    };
    socket.on('data', onData);
    socket.once('error', onError);
    socket.once('close', onClose);
  });

const writeFragments = async (socket, chunks) => {
  for (let i = 0; i < chunks.length; i++) {
    socket.write(chunks[i]);
    if (i + 1 < chunks.length) await delay(20);
  }
};

const createServer = (t, options = {}) => {
  const server = new IceServer({ port: 0, ...options });
  t.after(() => server.close());
  return server;
};

const closeTcpListener = (server) =>
  new Promise((resolve, reject) => {
    server.close((error) => {
      if (error?.code === 'ERR_SERVER_NOT_RUNNING') resolve();
      else if (error) reject(error);
      else resolve();
    });
  });

test('STUN Binding server', { timeout: 30000 }, async (t) => {
  const isIpv6 = await supportsIpv6(t);
  if (!isIpv6) {
    await t.test('IPv6 bind failure rejects listen', async (t) => {
      const server = createServer(t);
      const isUnsupported = (error) => IPV6_CODES.includes(error.code);
      await assert.rejects(server.listen(), isUnsupported);
      assert.deepStrictEqual(server.ports, { udp: 0, tcp: 0, tls: 0 });
      await server.close();
    });
    t.diagnostic('Binding round trips require an IPv6 listener');
    return;
  }

  await t.test(
    'constructor owns no sockets and close is idempotent',
    async (t) => {
      const server = createServer(t);
      assert.deepStrictEqual(server.ports, { udp: 0, tcp: 0, tls: 0 });
      assert.deepStrictEqual(server.stats(), {
        allocations: 0,
        sent: 0,
        received: 0,
        dropped: 0,
      });
      await server.close();
      await server.close();
    },
  );

  await t.test(
    'UDP4 returns the source and shared effective port',
    async (t) => {
      const server = createServer(t);
      await server.listen();
      await server.listen();
      assert.ok(server.ports.udp > 0);
      assert.strictEqual(server.ports.tcp, server.ports.udp);
      assert.strictEqual(server.ports.tls, 0);
      const socket = createUdp(t);
      await bindUdp(socket);
      const packet = request();
      const buffer = await exchangeUdp(socket, server.ports.udp, packet);
      checkResponse(buffer, packet, socket.address());
      const stats = server.stats();
      assert.deepStrictEqual(stats, {
        allocations: 0,
        sent: 0,
        received: 0,
        dropped: 0,
      });
      stats.sent = 123;
      assert.strictEqual(server.stats().sent, 0);
    },
  );

  await t.test('UDP6 returns the IPv6 source on the same port', async (t) => {
    const server = createServer(t, { listen: '127.0.0.1' });
    await server.listen();
    const socket = createUdp(t, 'udp6');
    await bindUdp(socket, 0, '::1');
    const packet = request();
    const buffer = await exchangeUdp(socket, server.ports.udp, packet, '::1');
    checkResponse(buffer, packet, socket.address());
  });

  await t.test(
    'UDP and TCP report distinct unknown attributes in 420',
    async (t) => {
      const server = createServer(t);
      await server.listen();
      const socket = createUdp(t);
      await bindUdp(socket);
      const value = Buffer.from([1]);
      const packet = request([
        { type: 0x0002, value },
        { type: 0x0002, value },
        { type: 0x0004, value },
        { type: 0xaaaa, value },
      ]);
      const buffer = await exchangeUdp(socket, server.ports.udp, packet);
      checkUnknownResponse(buffer, packet);
      const tcp = await connect(t, server.ports.tcp);
      const result = await Promise.all([
        readTcp(tcp, 1),
        writeFragments(tcp, [packet]),
      ]);
      checkUnknownResponse(result[0][0], packet);
    },
  );

  await t.test('unknown optional attributes are ignored', async (t) => {
    const server = createServer(t, { software: 'custom-stun' });
    await server.listen();
    const socket = createUdp(t);
    await bindUdp(socket);
    const packet = request([{ type: 0xaaaa, value: Buffer.from([1]) }]);
    const buffer = await exchangeUdp(socket, server.ports.udp, packet);
    checkResponse(buffer, packet, socket.address(), 'custom-stun');
  });

  await t.test(
    'malformed UDP and non-request messages are dropped',
    async (t) => {
      const server = createServer(t);
      await server.listen();
      const socket = createUdp(t);
      await bindUdp(socket);
      const packets = [];
      const onMessage = (buffer) => packets.push(buffer);
      socket.on('message', onMessage);
      t.after(() => socket.off('message', onMessage));
      const malformed = request();
      malformed.writeUInt16BE(1, 2);
      const invalid = [
        Buffer.from('not STUN'),
        malformed,
        request().subarray(0, 25),
        Buffer.concat([request(), Buffer.from([0])]),
        request([], 'indication'),
        request([], 'success'),
        request([], 'error'),
      ];
      for (let i = 0; i < invalid.length; i++) {
        await new Promise((resolve, reject) => {
          socket.send(invalid[i], server.ports.udp, '127.0.0.1', (error) => {
            if (error) reject(error);
            else resolve();
          });
        });
      }
      const packet = request();
      const buffer = await exchangeUdp(socket, server.ports.udp, packet);
      checkResponse(buffer, packet, socket.address());
      await delay(40);
      assert.strictEqual(packets.length, 1);
    },
  );

  await t.test('TCP accepts partial headers and bodies', async (t) => {
    const server = createServer(t);
    await server.listen();
    const socket = await connect(t, server.ports.tcp);
    const packet = request();
    const chunks = [
      packet.subarray(0, 3),
      packet.subarray(3, 21),
      packet.subarray(21),
    ];
    const result = await Promise.all([
      readTcp(socket, 1),
      writeFragments(socket, chunks),
    ]);
    checkResponse(result[0][0], packet, socket.address());
  });

  await t.test(
    'TCP separates coalesced requests and a trailing partial',
    async (t) => {
      const server = createServer(t);
      await server.listen();
      const socket = await connect(t, server.ports.tcp);
      const first = request();
      const second = request();
      const third = request();
      const chunks = [
        Buffer.concat([first, second, third.subarray(0, 9)]),
        third.subarray(9),
      ];
      const result = await Promise.all([
        readTcp(socket, 3),
        writeFragments(socket, chunks),
      ]);
      const packets = result[0];
      checkResponse(packets[0], first, socket.address());
      checkResponse(packets[1], second, socket.address());
      checkResponse(packets[2], third, socket.address());
    },
  );

  await t.test(
    'close waits for live clients and releases every listener',
    async (t) => {
      const server = createServer(t);
      await server.listen();
      const port = server.ports.udp;
      const client = await connect(t, port);
      const idle = await connect(t, port);
      const shutdownErrors = [];
      let isClosing = false;
      const onError = (error) => shutdownErrors.push({ error, isClosing });
      const waitForClose = (socket) =>
        new Promise((resolve) => {
          const onClose = () => {
            socket.off('error', onError);
            resolve();
          };
          socket.on('error', onError);
          socket.once('close', onClose);
        });
      const clientClosed = waitForClose(client);
      const idleClosed = waitForClose(idle);
      client.write(request().subarray(0, 3));
      isClosing = true;
      await Promise.all([
        server.close(),
        server.close(),
        clientClosed,
        idleClosed,
      ]);
      for (let i = 0; i < shutdownErrors.length; i++) {
        const failure = shutdownErrors[i];
        const { error } = failure;
        assert.ok(failure.isClosing);
        assert.strictEqual(error.code, 'ECONNRESET');
        assert.strictEqual(error.syscall, 'read');
      }
      if (shutdownErrors.length > 0) {
        t.diagnostic('Forced shutdown caused a TCP read reset');
      }
      assert.ok(client.closed);
      assert.ok(idle.closed);
      assert.deepStrictEqual(server.ports, { udp: 0, tcp: 0, tls: 0 });
      const replacement = createServer(t, { port });
      await replacement.listen();
      await replacement.close();
    },
  );

  await t.test(
    'fixed and automatic ports handle a TCP bind conflict',
    async (t) => {
      const occupied = net.createServer();
      t.after(() => closeTcpListener(occupied));
      const ready = once(occupied, 'listening');
      occupied.listen({ port: 0, host: '0.0.0.0' });
      await ready;
      const port = occupied.address().port;
      const warnings = [];
      const logger = {
        log: () => {},
        info: () => {},
        warn: (line) => warnings.push(line),
        debug: () => {},
        error: () => {},
      };
      const server = createServer(t, { port, console: logger });
      await assert.rejects(server.listen(), { code: 'EADDRINUSE' });
      assert.ok(warnings.some((line) => line.includes('EADDRINUSE')));
      assert.deepStrictEqual(server.ports, { udp: 0, tcp: 0, tls: 0 });
      const udp4 = createUdp(t);
      const udp6 = createUdp(t, 'udp6');
      await bindUdp(udp4, port, '0.0.0.0');
      await bindUdp(udp6, port, '::');
      await server.close();
      await closeUdp(udp4);
      await closeUdp(udp6);

      warnings.length = 0;
      const automatic = createServer(t, { console: logger });
      const bindListener = automatic.bindUdp.bind(automatic);
      let firstPort = port;
      automatic.bindUdp = (transport, address, requested) => {
        if (transport !== 'udp4' || requested !== 0) {
          return bindListener(transport, address, requested);
        }
        const selected = firstPort;
        firstPort = 0;
        return bindListener(transport, address, selected);
      };
      await automatic.listen();
      assert.ok(
        warnings.some((line) => line.startsWith('ICE tcp: listen EADDRINUSE')),
      );
      assert.ok(automatic.ports.udp > 0);
      assert.notStrictEqual(automatic.ports.udp, port);
      assert.strictEqual(automatic.ports.tcp, automatic.ports.udp);

      await closeTcpListener(occupied);
      const replacement = createServer(t, { port });
      await replacement.listen();
      await replacement.close();
    },
  );
});
