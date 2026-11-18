'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { test } = require('node:test');

const { credentials, iceServers } = require('../metaice.js');
const { createNonce, checkNonce } = require('../lib/credentials.js');

const NOW = 1_700_000_000_999;
const ADDRESS = '192.0.2.1';

test('REST credentials use expiry, peer and the configured TTL', () => {
  const secret = crypto.randomBytes(32).toString('hex');
  const options = { secret, peer: 'peer-ada', now: NOW };
  const result = credentials(options);
  const expiry = Math.floor(NOW / 1000) + 86400;
  assert.equal(result.expiry, expiry);
  assert.equal(result.username, `${expiry}:peer-ada`);
  const expected = crypto
    .createHmac('sha1', secret)
    .update(result.username)
    .digest('base64');
  assert.equal(result.credential, expected);
  assert.deepEqual(credentials(options), result);
  const shorter = credentials({ ...options, credentialTtl: 60 });
  assert.equal(shorter.expiry, Math.floor(NOW / 1000) + 60);
  assert.notEqual(shorter.credential, result.credential);
  const other = credentials({ ...options, peer: 'peer-bob' });
  assert.notEqual(other.credential, result.credential);
});

test('nonces are stateless, address bound and valid for ten minutes', () => {
  const secret = crypto.randomBytes(32).toString('hex');
  const nonce = createNonce(secret, ADDRESS, NOW);
  assert.equal(createNonce(secret, ADDRESS, NOW), nonce);
  assert.ok(checkNonce(secret, nonce, ADDRESS, NOW));
  assert.ok(checkNonce(secret, Buffer.from(nonce), ADDRESS, NOW + 599000));
  assert.equal(checkNonce(secret, nonce, ADDRESS, NOW + 600000), false);
  assert.equal(checkNonce(secret, nonce, ADDRESS, NOW - 1000), false);
  assert.equal(checkNonce(secret, nonce, '192.0.2.2', NOW), false);
  const otherSecret = crypto.randomBytes(32).toString('hex');
  assert.equal(checkNonce(otherSecret, nonce, ADDRESS, NOW), false);
  const forged = crypto.randomBytes(80).toString('base64url');
  assert.equal(checkNonce(secret, forged, ADDRESS, NOW), false);
  assert.equal(checkNonce(secret, null, ADDRESS, NOW), false);
  assert.equal(checkNonce(secret, 'a'.repeat(257), ADDRESS, NOW), false);
  const text = Buffer.from(nonce, 'base64url').toString();
  const changed = `${text.slice(0, -1)}${text.endsWith('0') ? '1' : '0'}`;
  const tampered = Buffer.from(changed).toString('base64url');
  assert.equal(checkNonce(secret, tampered, ADDRESS, NOW), false);
});

test('ICE list advertises STUN and gates TURN on secret and peer', () => {
  const secret = crypto.randomBytes(32).toString('hex');
  const base = { name: 'turn.example.com', peer: 'peer', now: NOW };
  const stun = { urls: ['stun:turn.example.com:3478'] };
  assert.deepEqual(iceServers(base), [stun]);
  assert.deepEqual(iceServers({ ...base, secret, peer: '' }), [stun]);
  const options = { ...base, secret, credentialTtl: 3600 };
  const identity = credentials(options);
  assert.deepEqual(iceServers(options), [
    stun,
    {
      urls: [
        'turn:turn.example.com:3478?transport=udp',
        'turn:turn.example.com:3478?transport=tcp',
      ],
      username: identity.username,
      credential: identity.credential,
    },
  ]);
});

test('ICE list uses selected name and ports without external entries', () => {
  const secret = crypto.randomBytes(32).toString('hex');
  const options = {
    name: '[2001:db8::1]',
    port: 12345,
    tlsPort: 12346,
    secret,
    peer: 'peer',
    now: NOW,
    host: 'ignored.example.com',
    external: [{ urls: ['stun:external.example.com:3478'] }],
  };
  const list = iceServers(options);
  assert.equal(list.length, 2);
  assert.deepEqual(list[0].urls, ['stun:[2001:db8::1]:12345']);
  assert.deepEqual(list[1].urls, [
    'turn:[2001:db8::1]:12345?transport=udp',
    'turn:[2001:db8::1]:12345?transport=tcp',
    'turns:[2001:db8::1]:12346?transport=tcp',
  ]);
});
