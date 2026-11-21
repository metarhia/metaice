'use strict';

const { IceServer } = require('./lib/server.js');
const { iceServers } = require('./lib/list.js');
const { credentials } = require('./lib/credentials.js');
const { isPrivate } = require('./lib/addresses.js');
const stun = require('./lib/stun.js');
const { start } = require('./lib/service.js');

const protocols = Object.freeze(['stun.turn', 'stun.nat-discovery']);

module.exports = {
  IceServer,
  iceServers,
  credentials,
  isPrivate,
  stun,
  start,
  protocols,
};
