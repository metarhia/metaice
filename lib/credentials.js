'use strict';

const crypto = require('node:crypto');

const CREDENTIAL_TTL = 24 * 60 * 60;
const NONCE_LIFETIME = 600;

const password = (secret, username) => {
  const hmac = crypto.createHmac('sha1', secret).update(username);
  return hmac.digest('base64');
};

const credentials = (options) => {
  const { secret, peer } = options;
  const now = options.now ?? Date.now();
  const credentialTtl = options.credentialTtl ?? CREDENTIAL_TTL;
  const expiry = Math.floor(now / 1000) + credentialTtl;
  const username = `${expiry}:${peer}`;
  const credential = password(secret, username);
  return { username, credential, expiry };
};

const nonceMac = (secret, time, address) => {
  const hmac = crypto.createHmac('sha256', secret);
  return hmac.update(`${time}:${address}`).digest();
};

const createNonce = (secret, address, now = Date.now()) => {
  const time = Math.floor(now / 1000);
  const hmac = nonceMac(secret, time, address);
  const text = `${time}.${hmac.toString('hex')}`;
  return Buffer.from(text).toString('base64url');
};

const checkNonce = (secret, value, address, now = Date.now()) => {
  if (!value || value.length > 256) return false;
  const text = Buffer.from(value.toString(), 'base64url').toString();
  const match = /^(\d{1,12})\.([a-f0-9]{64})$/.exec(text);
  if (!match) return false;
  const time = Number(match[1]);
  const age = Math.floor(now / 1000) - time;
  const expected = nonceMac(secret, time, address);
  const supplied = Buffer.from(match[2], 'hex');
  const isValid = crypto.timingSafeEqual(expected, supplied);
  return isValid && age >= 0 && age < NONCE_LIFETIME;
};

module.exports = {
  CREDENTIAL_TTL,
  password,
  credentials,
  createNonce,
  checkNonce,
};
