'use strict';

const { credentials } = require('./credentials.js');
const { DEFAULT_PORT } = require('./server.js');

const iceServers = (options) => {
  const { name, secret, peer } = options;
  const port = options.port ?? DEFAULT_PORT;
  const tlsPort = options.tlsPort ?? 0;
  const list = [{ urls: [`stun:${name}:${port}`] }];
  if (!secret || !peer) return list;
  const urls = [
    `turn:${name}:${port}?transport=udp`,
    `turn:${name}:${port}?transport=tcp`,
  ];
  if (tlsPort) urls.push(`turns:${name}:${tlsPort}?transport=tcp`);
  const { username, credential } = credentials(options);
  list.push({ urls, username, credential });
  return list;
};

module.exports = { iceServers };
