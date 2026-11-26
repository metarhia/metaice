'use strict';

const crypto = require('node:crypto');
const dgram = require('node:dgram');
const { once } = require('node:events');
const net = require('node:net');

const stun = require('./stun.js');
const { isPrivate, mappedAddress } = require('./addresses.js');
const { closeSocket, isDatagram } = require('./sockets.js');

const { ATTRIBUTES } = stun;
const DATA_INDICATION = stun.typeOf(stun.METHODS.data, 'indication');
const PEER_SIZES = { 1: 8, 2: 20 };
const RELAY_FAMILIES = {
  IPv4: { type: 'udp4', wildcard: '0.0.0.0', version: 4 },
  IPv6: { type: 'udp6', wildcard: '::', version: 6 },
};
const MAX_PERMISSIONS = 1024;
const MAX_UDP_PAYLOAD = 65507;
const MAX_INDICATION_DATA = 65400;
const FIRST_CHANNEL = 0x4000;
const LAST_CHANNEL = 0x4fff;

const bindRelay = async (relay, port, address) => {
  try {
    relay.bind(port, address);
    await once(relay, 'listening');
    return true;
  } catch {
    return false;
  }
};

const settleRelay = async (opening) => {
  try {
    return await opening;
  } catch {
    return null;
  }
};

const readPeer = (attribute, transactionId) => {
  if (!attribute) return null;
  const { value } = attribute;
  const size = PEER_SIZES[value[1]];
  if (value.length !== size) return null;
  const peer = stun.readAddress(value, transactionId);
  return peer.port === 0 ? null : peer;
};

class Allocation {
  constructor(server, options) {
    const { id, client, remote, auth, family, address, lifetime } = options;
    const now = Date.now();
    this.server = server;
    this.id = id;
    this.client = client;
    this.remote = remote;
    this.username = auth.username;
    this.peer = auth.peer;
    this.relay = null;
    this.opening = null;
    this.closePromise = null;
    this.onError = null;
    this.onMessage = null;
    this.port = 0;
    this.relayKey = '';
    this.family = family;
    this.address = address;
    this.ready = false;
    this.created = now;
    this.expires = now + lifetime * 1000;
    this.permissions = new Map();
    this.channels = new Map();
    this.peers = new Map();
    this.tokens = server.options.relayBitrate / 8;
    this.sampled = now;
    this.sent = 0;
    this.received = 0;
    this.dropped = 0;
    this.closed = false;
    this.isLogged = false;
  }

  async openRelay() {
    const { relayPorts, listen } = this.server.options;
    const { type, wildcard, version } = RELAY_FAMILIES[this.family];
    const ipv6Only = version === 6;
    const address = net.isIP(listen) === version ? listen : wildcard;
    for (let port = relayPorts[0]; port <= relayPorts[1]; port++) {
      if (this.closed || this.server.isClosing) return null;
      const key = `${type}:${port}`;
      if (this.server.relayPorts.has(key)) continue;
      this.server.relayPorts.add(key);
      const relay = dgram.createSocket({ type, ipv6Only });
      const isBound = await bindRelay(relay, port, address);
      if (!isBound) {
        await closeSocket(relay);
        this.server.relayPorts.delete(key);
        continue;
      }
      this.port = port;
      this.relayKey = key;
      this.relay = relay;
      const onError = (error) => {
        this.server.options.console.warn(`TURN relay UDP: ${error.code}`);
        this.server.discard(this);
      };
      const onMessage = (buffer, remote) => this.fromPeer(buffer, remote);
      this.onError = onError;
      this.onMessage = onMessage;
      relay.on('error', onError);
      relay.on('message', onMessage);
      return relay;
    }
    return null;
  }

  peerError(peer) {
    if (!peer) return 400;
    const isBlocked = isPrivate(peer.address);
    if (!this.server.options.allowPrivatePeers && isBlocked) return 403;
    if (peer.family !== this.family) return 443;
    return 0;
  }

  permission(message) {
    const peers = [];
    for (let i = 0; i < message.attributes.length; i++) {
      const attribute = message.attributes[i];
      if (attribute.type !== ATTRIBUTES.xorPeerAddress) continue;
      const peer = readPeer(attribute, message.transactionId);
      const code = this.peerError(peer);
      if (code) return { code };
      peers.push(peer);
    }
    if (!peers.length) return { code: 400 };
    const addresses = new Set(this.permissions.keys());
    for (let i = 0; i < peers.length; i++) addresses.add(peers[i].address);
    if (addresses.size > MAX_PERMISSIONS) return { code: 508 };
    const expires = Date.now() + this.server.options.permissionLifetime * 1000;
    for (let i = 0; i < peers.length; i++) {
      this.permissions.set(peers[i].address, expires);
    }
    return { attributes: [] };
  }

  channelBind(message) {
    const number = stun.find(message, ATTRIBUTES.channelNumber)?.value;
    if (!number || number.length !== 4) return { code: 400 };
    const channel = number.readUInt16BE(0);
    const isInRange = channel >= FIRST_CHANNEL && channel <= LAST_CHANNEL;
    if (!isInRange) return { code: 400 };
    const attribute = stun.find(message, ATTRIBUTES.xorPeerAddress);
    const peer = readPeer(attribute, message.transactionId);
    const code = this.peerError(peer);
    if (code) return { code };
    this.expireBindings(Date.now());
    const id = `${peer.address}:${peer.port}`;
    const bound = this.channels.get(channel);
    if (bound && bound.id !== id) return { code: 400 };
    const existing = this.peers.get(id);
    if (existing && existing !== channel) return { code: 400 };
    const now = Date.now();
    const expires = now + this.server.options.channelLifetime * 1000;
    this.channels.set(channel, { id, peer, expires });
    this.peers.set(id, channel);
    const permission = now + this.server.options.permissionLifetime * 1000;
    this.permissions.set(peer.address, permission);
    return { attributes: [] };
  }

  permitted(address) {
    if (!this.ready || this.closed) return false;
    const now = Date.now();
    if (this.expires <= now) return false;
    return (this.permissions.get(address) ?? 0) > now;
  }

  take(sizeBytes) {
    const now = Date.now();
    const capacity = this.server.options.relayBitrate / 8;
    const elapsed = Math.max(0, now - this.sampled);
    const refill = (elapsed * capacity) / 1000;
    this.tokens = Math.min(capacity, this.tokens + refill);
    this.sampled = now;
    if (sizeBytes > this.tokens) {
      this.dropped += sizeBytes;
      return false;
    }
    this.tokens -= sizeBytes;
    return true;
  }

  toPeer(peer, data) {
    if (!this.permitted(peer.address) || this.peerError(peer)) return;
    if (data.length > MAX_UDP_PAYLOAD || !this.take(data.length)) return;
    try {
      this.relay.send(data, peer.port, peer.address, (error) => {
        if (error) this.dropped += data.length;
        else this.sent += data.length;
      });
    } catch {
      this.dropped += data.length;
    }
  }

  indication(message) {
    const attribute = stun.find(message, ATTRIBUTES.xorPeerAddress);
    const peer = readPeer(attribute, message.transactionId);
    const data = stun.find(message, ATTRIBUTES.data)?.value;
    if (peer && data) this.toPeer(peer, data);
  }

  channelData(buffer) {
    if (buffer.length < 4) return;
    const size = buffer.readUInt16BE(2);
    const end = size + 4;
    if (end > buffer.length || buffer.length > Math.ceil(end / 4) * 4) return;
    const bound = this.channels.get(buffer.readUInt16BE(0));
    if (!bound || bound.expires <= Date.now()) return;
    this.toPeer(bound.peer, buffer.subarray(4, end));
  }

  fromPeer(buffer, remote) {
    const peer = mappedAddress(remote);
    if (!this.permitted(peer.address) || this.peerError(peer)) return;
    if (!this.take(buffer.length)) return;
    const packet = this.peerPacket(peer, buffer);
    if (!packet) return;
    this.received += buffer.length;
    this.server.write(this.client, packet, this.remote);
  }

  peerPacket(peer, buffer) {
    const id = `${peer.address}:${peer.port}`;
    const channel = this.peers.get(id);
    const bound = this.channels.get(channel);
    if (bound && bound.expires > Date.now()) {
      const isUdp = isDatagram(this.client);
      const size = isUdp ? buffer.length : Math.ceil(buffer.length / 4) * 4;
      const packet = Buffer.alloc(4 + size);
      packet.writeUInt16BE(channel, 0);
      packet.writeUInt16BE(buffer.length, 2);
      buffer.copy(packet, 4);
      return packet;
    }
    if (buffer.length > MAX_INDICATION_DATA) return null;
    const transactionId = crypto.randomBytes(12);
    const value = stun.writeAddress(peer, transactionId);
    const attributes = [
      { type: ATTRIBUTES.xorPeerAddress, value },
      { type: ATTRIBUTES.data, value: buffer },
    ];
    const type = DATA_INDICATION;
    return stun.encode({ type, transactionId, attributes, fingerprint: true });
  }

  expireBindings(now) {
    for (const channel of this.channels.keys()) {
      const bound = this.channels.get(channel);
      if (bound.expires > now) continue;
      this.channels.delete(channel);
      this.peers.delete(bound.id);
    }
    for (const address of this.permissions.keys()) {
      const expires = this.permissions.get(address);
      if (expires <= now) this.permissions.delete(address);
    }
  }

  close() {
    if (!this.closePromise) {
      this.closed = true;
      this.ready = false;
      if (this.server.allocations.get(this.id) === this) {
        this.server.allocations.delete(this.id);
      }
      this.permissions.clear();
      this.channels.clear();
      this.peers.clear();
      this.closePromise = this.dispose();
      this.server.closingAllocations.add(this.closePromise);
    }
    return this.closePromise;
  }

  async dispose() {
    try {
      const opened = await settleRelay(this.opening);
      if (!this.relay) this.relay = opened;
      if (this.relay) {
        await closeSocket(this.relay);
        if (this.onError) this.relay.off('error', this.onError);
        if (this.onMessage) this.relay.off('message', this.onMessage);
        this.server.relayPorts.delete(this.relayKey);
        if (this.isLogged) this.server.log(this, 'delete');
      }
    } finally {
      this.server.closingAllocations.delete(this.closePromise);
    }
  }
}

module.exports = { Allocation };
