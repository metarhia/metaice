'use strict';

const crypto = require('node:crypto');
const net = require('node:net');

const { IceServer, stun, credentials } = require('../metaice.js');
const { createNonce } = require('../lib/credentials.js');

const TRANSPORT = { type: 0x0019, value: Buffer.from([17, 0, 0, 0]) };

const loadIce = (options = {}) => {
  const logs = [];
  const logger = {
    log: (text) => logs.push(text),
    info: (text) => logs.push(text),
    warn: (text) => logs.push(text),
    debug: (text) => logs.push(text),
    error: (text) => logs.push(text),
  };
  const ice = new IceServer({ ...options, console: logger });
  return { ice, stun, config: ice.options, logs };
};

const turnOptions = (allowPrivatePeers = true) => ({
  secret: crypto.randomBytes(32).toString('hex'),
  allowPrivatePeers,
  publicAddress: '127.0.0.1',
});

const clientAuth = (ice, stun, peer, address = '127.0.0.1') => {
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

const packet = (stun, method, attributes, auth = null, options = {}) => {
  const transactionId = options.transactionId ?? crypto.randomBytes(12);
  const values = attributes.slice();
  if (auth) {
    values.push({ type: 0x0006, value: Buffer.from(auth.username) });
    values.push({ type: 0x0014, value: Buffer.from(auth.realm) });
    values.push({ type: 0x0015, value: Buffer.from(auth.nonce) });
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

const codeOf = (stun, buffer) => {
  const message = stun.decode(buffer);
  const value = stun.find(message, 0x0009)?.value;
  return value ? value[2] * 100 + value[3] : 0;
};

const peerAttribute = (stun, transactionId, port, address = '127.0.0.1') => {
  const family = net.isIP(address) === 4 ? 'IPv4' : 'IPv6';
  const value = stun.writeAddress({ address, port, family }, transactionId);
  return { type: 0x0012, value };
};

module.exports = {
  loadIce,
  turnOptions,
  clientAuth,
  packet,
  codeOf,
  peerAttribute,
  TRANSPORT,
};
