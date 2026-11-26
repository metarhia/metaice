'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const dgram = require('node:dgram');
const { once } = require('node:events');
const net = require('node:net');
const { setTimeout: delay } = require('node:timers/promises');

const { IceServer, stun, credentials } = require('../metaice.js');
const { createNonce } = require('../lib/credentials.js');

const { ATTRIBUTES } = stun;
const TRANSPORT = {
  type: ATTRIBUTES.requestedTransport,
  value: Buffer.from([17, 0, 0, 0]),
};
const DGRAM_CLOSED = 'ERR_SOCKET_DGRAM_NOT_RUNNING';
const SERVER_CLOSED = 'ERR_SERVER_NOT_RUNNING';

const createLogger = (logs) => ({
  log: (value) => logs.push(value),
  info: (value) => logs.push(value),
  warn: (value) => logs.push(value),
  debug: (value) => logs.push(value),
  error: (value) => logs.push(value),
});

const loadIce = (options = {}) => {
  const logs = [];
  const logger = createLogger(logs);
  const ice = new IceServer({ ...options, console: logger });
  return { ice, stun, config: ice.options, logs };
};

const turnOptions = (allowPrivatePeers = true) => {
  const secret = crypto.randomBytes(32).toString('hex');
  const publicAddress = '127.0.0.1';
  return { secret, allowPrivatePeers, publicAddress };
};

const clientAuth = (ice, peer, address = '127.0.0.1') => {
  const identity = credentials({ ...ice.options, peer });
  const { realm, secret } = ice.options;
  const key = stun.longTermKey(identity.username, realm, identity.credential);
  return {
    username: identity.username,
    realm,
    nonce: createNonce(secret, address),
    key,
  };
};

const packet = (method, attributes, auth = null, options = {}) => {
  const transactionId = options.transactionId ?? crypto.randomBytes(12);
  const values = attributes.slice();
  if (auth) {
    values.push({
      type: ATTRIBUTES.username,
      value: Buffer.from(auth.username),
    });
    values.push({ type: ATTRIBUTES.realm, value: Buffer.from(auth.realm) });
    values.push({ type: ATTRIBUTES.nonce, value: Buffer.from(auth.nonce) });
  }
  const kind = options.kind ?? 'request';
  const type = stun.typeOf(stun.METHODS[method], kind);
  return stun.encode({
    type,
    transactionId,
    attributes: values,
    key: auth?.key,
    fingerprint: true,
  });
};

const codeOf = (buffer) => {
  const message = stun.decode(buffer);
  const value = stun.find(message, ATTRIBUTES.errorCode)?.value;
  return value ? value[2] * 100 + value[3] : 0;
};

const expectCode = (reply, code, key) => {
  assert.equal(codeOf(reply), code);
  const message = stun.decode(reply);
  assert.equal(stun.verifyFingerprint(reply, message), true);
  if (key) assert.equal(stun.verifyIntegrity(reply, message, key), true);
};

const peerAttribute = (transactionId, port, address = '127.0.0.1') => {
  const family = net.isIP(address) === 4 ? 'IPv4' : 'IPv6';
  const value = stun.writeAddress({ address, port, family }, transactionId);
  return { type: ATTRIBUTES.xorPeerAddress, value };
};

const requestPeer = (port, attributes = []) => {
  const transactionId = crypto.randomBytes(12);
  const peer = peerAttribute(transactionId, port);
  return { transactionId, attributes: attributes.concat([peer]) };
};

const channelNumber = (number) => {
  const value = Buffer.alloc(4);
  value.writeUInt16BE(number, 0);
  return { type: ATTRIBUTES.channelNumber, value };
};

const channelPacket = (number, data, isPadded = false) => {
  const size = isPadded ? Math.ceil(data.length / 4) * 4 : data.length;
  const buffer = Buffer.alloc(4 + size);
  buffer.writeUInt16BE(number, 0);
  buffer.writeUInt16BE(data.length, 2);
  data.copy(buffer, 4);
  return buffer;
};

const closeUdp = (socket) =>
  new Promise((resolve, reject) => {
    const finish = (error) => {
      if (error && error.code !== DGRAM_CLOSED) reject(error);
      else resolve();
    };
    try {
      socket.close(finish);
    } catch (error) {
      finish(error);
    }
  });

const closeServer = (server) =>
  new Promise((resolve, reject) => {
    server.close((error) => {
      if (error && error.code !== SERVER_CLOSED) reject(error);
      else resolve();
    });
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

const listenTcp = async (port) => {
  const server = net.createServer();
  const ready = once(server, 'listening');
  server.listen({ port, host: '127.0.0.1' });
  await ready;
  await closeServer(server);
};

const waitTcpFree = async (port) => {
  const deadline = Date.now() + 2000;
  let failure = new Error('Port stayed busy');
  while (Date.now() < deadline) {
    try {
      await listenTcp(port);
      return;
    } catch (error) {
      failure = error;
      if (error.code !== 'EADDRINUSE') throw error;
      await delay(20);
    }
  }
  throw failure;
};

module.exports = {
  TRANSPORT,
  createLogger,
  loadIce,
  turnOptions,
  clientAuth,
  packet,
  codeOf,
  expectCode,
  peerAttribute,
  requestPeer,
  channelNumber,
  channelPacket,
  closeUdp,
  closeServer,
  reservePort,
  reserveRange,
  waitTcpFree,
};
