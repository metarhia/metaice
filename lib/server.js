'use strict';

const dgram = require('node:dgram');
const fs = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const tls = require('node:tls');

const stun = require('./stun.js');
const { Allocation } = require('./allocation.js');
const { isPrivate } = require('./addresses.js');
const authentication = require('./credentials.js');
const { CREDENTIAL_TTL, password, createNonce, checkNonce } = authentication;

const ATTRIBUTE_NAMES = Object.keys(stun.ATTRIBUTES);
const KNOWN_ATTRIBUTES = new Set(
  ATTRIBUTE_NAMES.map((name) => stun.ATTRIBUTES[name]),
);
KNOWN_ATTRIBUTES.add(0x0017);
KNOWN_ATTRIBUTES.add(0x001a);
const REASONS = {
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  420: 'Unknown Attribute',
  437: 'Allocation Mismatch',
  438: 'Stale Nonce',
  440: 'Address Family not Supported',
  441: 'Wrong Credentials',
  442: 'Unsupported Transport Protocol',
  443: 'Peer Address Family Mismatch',
  486: 'Allocation Quota Reached',
  508: 'Insufficient Capacity',
};
const CLOSED_CODES = ['ERR_SOCKET_DGRAM_NOT_RUNNING', 'ERR_SERVER_NOT_RUNNING'];
const EMPTY_BUFFER = Buffer.alloc(0);

const bindListener = (socket, start) =>
  new Promise((resolve, reject) => {
    let cleanup = null;
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onReady = () => {
      cleanup();
      resolve();
    };
    cleanup = () => {
      socket.off('error', onError);
      socket.off('listening', onReady);
    };
    socket.once('error', onError);
    socket.once('listening', onReady);
    try {
      start();
    } catch (error) {
      onError(error);
    }
  });

const closeListener = (listener) =>
  new Promise((resolve, reject) => {
    const { socket, onError, onMessage, onConnection } = listener;
    const finish = (error) => {
      socket.off('error', onError);
      if (onMessage) socket.off('message', onMessage);
      if (onConnection) socket.off('connection', onConnection);
      if (listener.onSecureConnection) {
        socket.off('secureConnection', listener.onSecureConnection);
      }
      if (error && !CLOSED_CODES.includes(error.code)) reject(error);
      else resolve();
    };
    try {
      socket.close(finish);
    } catch (error) {
      finish(error);
    }
  });

const frameLength = (buffer) => {
  if (buffer.length === 0) return 0;
  if (buffer[0] >= 0x40 && buffer[0] <= 0x4f) {
    if (buffer.length < 4) return 0;
    const length = buffer.readUInt16BE(2);
    return 4 + Math.ceil(length / 4) * 4;
  }
  if (buffer[0] > 0x3f) return -1;
  if (buffer.length < stun.HEADER_SIZE) return 0;
  if (!stun.isStun(buffer)) return -1;
  const length = buffer.readUInt16BE(2);
  if (length % 4 !== 0) return -1;
  return stun.HEADER_SIZE + length;
};

const unknownAttributes = (message) => {
  const types = [];
  for (let i = 0; i < message.attributes.length; i++) {
    const { type } = message.attributes[i];
    const isUnknown = type < 0x8000 && !KNOWN_ATTRIBUTES.has(type);
    if (isUnknown && !types.includes(type)) types.push(type);
  }
  return types;
};

const encodeTypes = (types) => {
  const value = Buffer.alloc(types.length * 2);
  for (let i = 0; i < types.length; i++) {
    value.writeUInt16BE(types[i], i * 2);
  }
  return value;
};

const coveredAttributes = (message) => {
  const attributes = [];
  for (let i = 0; i < message.attributes.length; i++) {
    const attribute = message.attributes[i];
    attributes.push(attribute);
    if (attribute.type === stun.ATTRIBUTES.messageIntegrity) break;
  }
  return { ...message, attributes };
};

const seconds = (lifetime) => {
  const value = Buffer.alloc(4);
  value.writeUInt32BE(lifetime, 0);
  return { type: 0x000d, value };
};

const tuple = (transport, local, remote) => {
  const server = `${local.address}:${local.port}`;
  return `${transport}:${server}:${remote.address}:${remote.port}`;
};

class IceServer {
  constructor(options = {}) {
    this.options = {
      listen: options.listen ?? '0.0.0.0',
      port: options.port ?? 3478,
      tlsPort: options.tlsPort ?? 0,
      tls: options.tls ?? null,
      publicAddress: options.publicAddress ?? '',
      relayPorts: options.relayPorts?.slice() ?? [49160, 49359],
      secret: options.secret ?? '',
      credentialTtl: options.credentialTtl ?? CREDENTIAL_TTL,
      allocationsPerPeer: options.allocationsPerPeer ?? 10,
      allocationLifetime: options.allocationLifetime?.slice() ?? [600, 3600],
      permissionLifetime: options.permissionLifetime ?? 300,
      channelLifetime: options.channelLifetime ?? 600,
      relayBitrate: options.relayBitrate ?? 5_000_000,
      allowPrivatePeers: options.allowPrivatePeers ?? false,
      realm: options.realm ?? 'metaice',
      software: options.software ?? 'metaice',
      console: options.console ?? globalThis.console,
    };
    this.ports = { udp: 0, tcp: 0, tls: 0 };
    this.software = Buffer.from(this.options.software);
    this.listeners = [];
    this.connections = new Map();
    this.handshakes = new Map();
    this.closingConnections = new Set();
    this.allocations = new Map();
    this.responses = new Map();
    this.relayPorts = new Set();
    this.pendingRequests = new Set();
    this.closingAllocations = new Set();
    this.timer = null;
    this.listenPromise = null;
    this.disposePromise = null;
    this.closePromise = null;
    this.isClosing = false;
  }

  listen() {
    if (this.isClosing) {
      return Promise.reject(new Error('ICE server is closed'));
    }
    if (!this.listenPromise) this.listenPromise = this.open();
    return this.listenPromise;
  }

  async open() {
    try {
      const { listen, port } = this.options;
      const udp = await this.bindUdp('udp4', listen, port);
      this.ports.udp = udp.address().port;
      if (this.isClosing) throw new Error('ICE server is closed');
      await this.bindUdp('udp6', '::', this.ports.udp);
      if (this.isClosing) throw new Error('ICE server is closed');
      await this.bindTcp(this.ports.udp);
      this.ports.tcp = this.ports.udp;
      if (this.isClosing) throw new Error('ICE server is closed');
      if (this.options.tlsPort) {
        await this.bindTls(this.options.tlsPort);
        if (this.isClosing) throw new Error('ICE server is closed');
      }
      this.schedule();
    } catch (error) {
      await this.dispose();
      throw error;
    }
  }

  async bindUdp(transport, address, port) {
    const ipv6Only = transport === 'udp6';
    const socket = dgram.createSocket({ type: transport, ipv6Only });
    const onError = (error) => {
      this.options.console.warn(`ICE ${transport}: ${error.message}`);
    };
    const listener = {
      socket,
      transport,
      onError,
      onMessage: null,
      onConnection: null,
      onSecureConnection: null,
    };
    const onMessage = (buffer, remote) => {
      this.receive(listener, buffer, remote).catch(() => {
        this.options.console.warn('ICE UDP request failed');
      });
    };
    listener.onMessage = onMessage;
    this.listeners.push(listener);
    socket.on('error', onError);
    socket.on('message', onMessage);
    await bindListener(socket, () => socket.bind({ port, address }));
    return socket;
  }

  async bindTcp(port) {
    const socket = net.createServer();
    const transport = 'tcp';
    const onError = (error) => {
      this.options.console.warn(`ICE ${transport}: ${error.message}`);
    };
    const onMessage = null;
    const onConnection = (client) => this.accept(client, transport);
    const onSecureConnection = null;
    const listener = {
      socket,
      transport,
      onError,
      onMessage,
      onConnection,
      onSecureConnection,
    };
    this.listeners.push(listener);
    socket.on('error', onError);
    socket.on('connection', onConnection);
    const host = this.options.listen;
    await bindListener(socket, () => socket.listen({ port, host }));
  }

  async bindTls(port) {
    const paths = this.options.tls;
    const hasPaths =
      paths &&
      typeof paths.key === 'string' &&
      typeof paths.cert === 'string' &&
      paths.key &&
      paths.cert;
    if (!hasPaths) throw new Error('TLS requires key and cert PEM file paths');
    const key = await fs.readFile(paths.key);
    const cert = await fs.readFile(paths.cert);
    if (this.isClosing) throw new Error('ICE server is closed');
    const socket = tls.createServer({ key, cert });
    const transport = 'tls';
    const onError = (error) => {
      this.options.console.warn(`ICE tls: ${error.message}`);
    };
    const onMessage = null;
    const onConnection = (client) => this.trackHandshake(client);
    const onSecureConnection = (client) => this.accept(client, transport);
    const listener = {
      socket,
      transport,
      onError,
      onMessage,
      onConnection,
      onSecureConnection,
    };
    this.listeners.push(listener);
    socket.on('error', onError);
    socket.on('connection', onConnection);
    socket.on('secureConnection', onSecureConnection);
    const host = this.options.listen;
    await bindListener(socket, () => socket.listen({ port, host }));
    this.ports.tls = socket.address().port;
  }

  trackHandshake(socket) {
    const closed = new Promise((resolve) => {
      socket.once('close', () => {
        this.handshakes.delete(socket);
        resolve();
      });
    });
    this.handshakes.set(socket, closed);
    if (this.isClosing) socket.destroy();
  }

  accept(socket, transport) {
    const onData = (chunk) => this.receiveStream(socket, chunk);
    const onError = (error) => {
      this.options.console.warn(`ICE ${transport} client: ${error.message}`);
    };
    const remote = {
      family: socket.remoteFamily,
      address: socket.remoteAddress,
      port: socket.remotePort,
    };
    const client = {
      socket,
      transport,
      id: tuple(transport, socket.address(), remote),
      buffer: EMPTY_BUFFER,
      draining: false,
      remote,
      closed: null,
    };
    client.closed = new Promise((resolve, reject) => {
      const onClose = async () => {
        socket.off('data', onData);
        socket.off('error', onError);
        this.connections.delete(socket);
        try {
          const allocation = this.allocations.get(client.id);
          if (allocation) await this.remove(allocation);
          resolve();
        } catch (error) {
          reject(error);
        } finally {
          this.closingConnections.delete(client.closed);
        }
      };
      socket.once('close', onClose);
    });
    this.connections.set(socket, client);
    this.closingConnections.add(client.closed);
    socket.on('data', onData);
    socket.on('error', onError);
    if (this.isClosing) socket.destroy();
  }

  receiveStream(socket, chunk) {
    const client = this.connections.get(socket);
    if (!client) return;
    const { buffer } = client;
    const hasBuffer = buffer.length > 0;
    client.buffer = hasBuffer ? Buffer.concat([buffer, chunk]) : chunk;
    if (client.draining) return;
    client.draining = true;
    this.drainStream(client).catch(() => {
      this.options.console.warn('ICE TCP request failed');
    });
  }

  async drainStream(client) {
    try {
      while (client.buffer.length > 0) {
        const length = frameLength(client.buffer);
        if (length < 0) {
          client.buffer = EMPTY_BUFFER;
          return;
        }
        const isShort = length === 0 || client.buffer.length < length;
        if (isShort) return;
        const packet = client.buffer.subarray(0, length);
        client.buffer = client.buffer.subarray(length);
        try {
          await this.receive(client, packet, client.remote);
        } catch {
          this.options.console.warn('ICE TCP request failed');
        }
      }
    } finally {
      client.draining = false;
    }
  }

  receive(client, buffer, remote) {
    if (this.isClosing) return Promise.resolve();
    const pending = this.dispatch(client, buffer, remote);
    this.pendingRequests.add(pending);
    return this.finishRequest(pending);
  }

  async finishRequest(pending) {
    try {
      await pending;
    } finally {
      this.pendingRequests.delete(pending);
    }
  }

  async dispatch(client, buffer, remote) {
    if (!buffer.length) return;
    const isUdp = client.transport.startsWith('udp');
    const transport = isUdp ? 'udp' : client.transport;
    const id = client.id ?? tuple(transport, client.socket.address(), remote);
    if (buffer[0] >= 0x40 && buffer[0] <= 0x4f) {
      const allocation = this.options.secret ? this.active(id) : null;
      if (allocation) allocation.channelData(buffer);
      return;
    }
    const decoded = stun.decode(buffer);
    if (!decoded || decoded.length + stun.HEADER_SIZE !== buffer.length) return;
    const message = coveredAttributes(decoded);
    const isBinding = message.method === stun.METHODS.binding;
    if (isBinding && message.kind === 'request') {
      const unknown = unknownAttributes(message);
      const reply = unknown.length
        ? { code: 420, unknown }
        : { attributes: this.binding(remote, message.transactionId) };
      this.reply(client, message, remote, reply, null);
      return;
    }
    if (!this.options.secret) return;
    if (message.kind === 'indication') {
      const allocation = this.active(id);
      const isSend = message.method === stun.METHODS.send;
      if (allocation && isSend && !unknownAttributes(message).length) {
        allocation.indication(message);
      }
      return;
    }
    if (message.kind !== 'request') return;
    const cacheId = `${id}:${message.transactionId.toString('hex')}`;
    const cached = this.responses.get(cacheId);
    const now = Date.now();
    const isCached = cached && (cached.pending || cached.expires > now);
    if (isCached) {
      if (cached.request.equals(buffer)) {
        const packet = await cached.promise;
        this.write(client, packet, remote);
      }
      return;
    }
    const auth = this.authenticate(buffer, message, remote);
    if (auth.code) {
      this.reply(client, message, remote, auth, auth.key);
      return;
    }
    if (this.responses.size >= 8192) return;
    const { promise, resolve } = Promise.withResolvers();
    const response = {
      request: Buffer.from(buffer),
      promise,
      pending: true,
      expires: now + 40000,
    };
    this.responses.set(cacheId, response);
    let result = { code: 508 };
    try {
      result = await this.request(client, id, message, remote, auth);
    } catch {
      this.options.console.warn('TURN request failed');
    }
    const packet = this.reply(client, message, remote, result, auth.key);
    response.pending = false;
    response.expires = Date.now() + 40000;
    resolve(packet);
  }

  binding(remote, transactionId) {
    const isV4 = remote.family === 4 || remote.family === 'IPv4';
    const family = isV4 ? 'IPv4' : 'IPv6';
    const mapped = { family, address: remote.address, port: remote.port };
    const address = stun.writeAddress(mapped, transactionId);
    const { xorMappedAddress, software } = stun.ATTRIBUTES;
    return [
      { type: xorMappedAddress, value: address },
      { type: software, value: this.software },
    ];
  }

  reply(client, message, remote, result, key) {
    const attributes = result.attributes?.slice() ?? [];
    if (result.code) {
      const reason = REASONS[result.code];
      const value = stun.errorCode(result.code, reason);
      attributes.push({ type: stun.ATTRIBUTES.errorCode, value });
      if (result.code === 401 || result.code === 438) {
        const realm = Buffer.from(this.options.realm);
        attributes.push({ type: 0x0014, value: realm });
        const nonce = createNonce(this.options.secret, remote.address);
        attributes.push({ type: 0x0015, value: Buffer.from(nonce) });
      }
      if (result.unknown) {
        attributes.push({ type: 0x000a, value: encodeTypes(result.unknown) });
      }
    }
    const kind = result.code ? 'error' : 'success';
    const type = stun.typeOf(message.method, kind);
    const { transactionId } = message;
    const packet = stun.encode({
      type,
      transactionId,
      attributes,
      key,
      fingerprint: true,
    });
    this.write(client, packet, remote);
    return packet;
  }

  write(client, packet, remote) {
    if (this.isClosing) return;
    try {
      if (!client.transport.startsWith('udp')) {
        if (!client.socket.destroyed) client.socket.write(packet);
      } else {
        client.socket.send(packet, remote.port, remote.address, () => {});
      }
    } catch {
      this.options.console.debug('ICE send failed');
    }
  }

  authenticate(buffer, message, remote) {
    const username = stun.find(message, 0x0006)?.value.toString();
    const realm = stun.find(message, 0x0014)?.value.toString();
    const nonce = stun.find(message, 0x0015)?.value;
    const match = /^(\d{1,12}):([A-Za-z0-9_-]{1,128})$/.exec(username ?? '');
    const expiry = match ? Number(match[1]) : 0;
    const isExpired = expiry <= Math.floor(Date.now() / 1000);
    if (!match || isExpired || realm !== this.options.realm) {
      return { code: 401, key: null };
    }
    const credential = password(this.options.secret, username);
    const key = stun.longTermKey(username, realm, credential);
    if (!stun.verifyIntegrity(buffer, message, key)) {
      return { code: 401, key: null };
    }
    if (!checkNonce(this.options.secret, nonce, remote.address)) {
      return { code: 438, key };
    }
    return { code: 0, username, peer: match[2], key };
  }

  async request(client, id, message, remote, auth) {
    const unknown = unknownAttributes(message);
    if (unknown.length) return { code: 420, unknown };
    if (message.method === stun.METHODS.allocate) {
      return this.allocate(client, id, message, remote, auth);
    }
    const allocation = this.active(id);
    if (!allocation) return { code: 437 };
    if (allocation.username !== auth.username) return { code: 441 };
    if (message.method === stun.METHODS.refresh) {
      const lifetime = this.lifetime(message, true);
      if (lifetime < 0) return { code: 400 };
      if (lifetime === 0) await this.remove(allocation);
      else allocation.expires = Date.now() + lifetime * 1000;
      return { attributes: [seconds(lifetime)] };
    }
    if (message.method === stun.METHODS.createPermission) {
      return allocation.permission(message);
    }
    if (message.method === stun.METHODS.channelBind) {
      return allocation.channelBind(message);
    }
    return { code: 400 };
  }

  active(id) {
    const allocation = this.allocations.get(id);
    if (!allocation || !allocation.ready) return null;
    if (allocation.expires <= Date.now()) {
      this.remove(allocation).catch(() => {
        this.options.console.warn('TURN allocation close failed');
      });
      return null;
    }
    return allocation;
  }

  lifetime(message, isRefresh = false) {
    const attribute = stun.find(message, 0x000d);
    const limits = this.options.allocationLifetime;
    if (!attribute) return limits[0];
    if (attribute.value.length !== 4) return -1;
    const lifetime = attribute.value.readUInt32BE(0);
    if (lifetime === 0 && isRefresh) return 0;
    return Math.min(limits[1], Math.max(limits[0], lifetime));
  }

  relayAddress(family) {
    const configured = this.options.publicAddress;
    if (configured) return net.isIP(configured) === family ? configured : '';
    const listen = this.options.listen;
    const isWildcard = listen === '0.0.0.0' || listen === '::';
    if (!isWildcard && net.isIP(listen) === family) return listen;
    const interfaces = os.networkInterfaces();
    const names = Object.keys(interfaces);
    let fallback = '';
    for (let i = 0; i < names.length; i++) {
      const addresses = interfaces[names[i]];
      for (let j = 0; j < addresses.length; j++) {
        const entry = addresses[j];
        if (entry.internal || net.isIP(entry.address) !== family) continue;
        if (entry.address.includes('%') || entry.scopeid > 0) continue;
        if (!isPrivate(entry.address)) return entry.address;
        if (!fallback) fallback = entry.address;
      }
    }
    return fallback;
  }

  async allocate(client, id, message, remote, auth) {
    if (this.active(id) || this.allocations.has(id)) return { code: 437 };
    const transport = stun.find(message, 0x0019)?.value;
    if (!transport || transport.length !== 4) return { code: 400 };
    if (transport[0] !== 17) return { code: 442 };
    const requested = stun.find(message, 0x0017)?.value;
    if (requested && requested.length !== 4) return { code: 400 };
    const familyCode = requested ? requested[0] : 1;
    if (familyCode !== 1 && familyCode !== 2) return { code: 440 };
    const family = familyCode === 1 ? 'IPv4' : 'IPv6';
    const address = this.relayAddress(familyCode === 1 ? 4 : 6);
    if (!address) return { code: 440 };
    const lifetime = this.lifetime(message);
    if (lifetime < 0) return { code: 400 };
    let count = 0;
    for (const allocation of this.allocations.values()) {
      if (allocation.peer === auth.peer) count++;
    }
    if (count >= this.options.allocationsPerPeer) return { code: 486 };
    const options = { id, client, remote, auth, family, address, lifetime };
    const allocation = new Allocation(this, options);
    this.allocations.set(id, allocation);
    allocation.opening = this.openRelay(allocation);
    const results = await Promise.allSettled([allocation.opening]);
    const opened = results[0];
    if (opened.status === 'rejected') {
      await this.remove(allocation);
      return { code: 508 };
    }
    const relay = opened.value;
    allocation.relay = relay;
    const disconnected =
      !client.transport.startsWith('udp') && client.socket.destroyed;
    if (!relay || allocation.closed || this.isClosing || disconnected) {
      await this.remove(allocation);
      return { code: 508 };
    }
    allocation.ready = true;
    const { transactionId } = message;
    const relayed = stun.writeAddress(allocation, transactionId);
    const attributes = this.binding(remote, transactionId);
    attributes.push({ type: 0x0016, value: relayed });
    attributes.push(seconds(lifetime));
    allocation.isLogged = true;
    this.log(allocation, 'create');
    return { attributes };
  }

  async openRelay(allocation) {
    if (this.isClosing) return null;
    return allocation.openRelay();
  }

  remove(allocation) {
    if (allocation.server !== this) {
      return Promise.reject(new Error('Allocation belongs to another server'));
    }
    return allocation.close();
  }

  schedule() {
    if (this.timer || this.isClosing || !this.options.secret) return;
    this.timer = setInterval(() => this.sweep(), 1000);
    this.timer.unref();
  }

  sweep(now = Date.now()) {
    for (const allocation of this.allocations.values()) {
      if (allocation.expires <= now) {
        this.remove(allocation).catch(() => {
          this.options.console.warn('TURN allocation close failed');
        });
      } else {
        allocation.expireBindings(now);
      }
    }
    for (const id of this.responses.keys()) {
      const response = this.responses.get(id);
      const isExpired = !response.pending && response.expires <= now;
      if (isExpired) this.responses.delete(id);
    }
  }

  log(allocation, action) {
    const seconds = Math.floor((Date.now() - allocation.created) / 1000);
    const { peer, port, sent, received, dropped } = allocation;
    const transport = allocation.client.transport;
    const client = transport.startsWith('udp') ? 'udp' : transport;
    this.options.console.log(
      `TURN ${action} peer=${peer} client=${client} relay=udp:${port} ` +
        `sent=${sent} received=${received} dropped=${dropped} ` +
        `seconds=${seconds}`,
    );
  }

  stats() {
    const totals = { allocations: 0, sent: 0, received: 0, dropped: 0 };
    for (const allocation of this.allocations.values()) {
      totals.allocations++;
      totals.sent += allocation.sent;
      totals.received += allocation.received;
      totals.dropped += allocation.dropped;
    }
    return totals;
  }

  close() {
    if (!this.closePromise) {
      this.isClosing = true;
      this.closePromise = this.stop();
    }
    return this.closePromise;
  }

  async stop() {
    if (this.listenPromise) {
      await Promise.allSettled([this.listenPromise]);
    }
    await this.dispose();
  }

  dispose() {
    if (!this.disposePromise) {
      this.isClosing = true;
      this.disposePromise = this.disposeResources();
    }
    return this.disposePromise;
  }

  async disposeResources() {
    clearInterval(this.timer);
    this.timer = null;
    const listeners = this.listeners.splice(0);
    const closed = listeners.map(closeListener);
    for (const client of this.connections.values()) {
      closed.push(client.closed);
      client.socket.destroy();
    }
    for (const socket of this.handshakes.keys()) {
      closed.push(this.handshakes.get(socket));
      socket.destroy();
    }
    for (const closing of this.closingConnections) closed.push(closing);
    for (const allocation of this.allocations.values()) {
      closed.push(this.remove(allocation));
    }
    for (const closing of this.closingAllocations) closed.push(closing);
    for (const pending of this.pendingRequests) closed.push(pending);
    const results = await Promise.allSettled(closed);
    this.responses.clear();
    this.ports.udp = 0;
    this.ports.tcp = 0;
    this.ports.tls = 0;
    const failure = results.find((result) => result.status === 'rejected');
    if (failure) throw failure.reason;
  }
}

module.exports = { IceServer };
