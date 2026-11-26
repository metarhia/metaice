'use strict';

const net = require('node:net');

const { DEFAULT_RELAY_PORTS, IceServer } = require('./server.js');
const { isV4Family } = require('./addresses.js');

const TURN_PROTOCOL = 'stun.turn';
const SLICE_ERROR = 'Invalid relay thread or port range';
const KNOWN_FAMILIES = ['IPv4', 4, 'IPv6', 6];

const loggerOf = (source, scope) => {
  const scoped = scope.console ?? source.console;
  return scoped ?? globalThis.console;
};

const turnSecret = (source, scope) => {
  const protocols = scope.protocols;
  if (!Array.isArray(protocols)) return source.secret;
  if (protocols.includes(TURN_PROTOCOL)) return source.secret;
  return '';
};

const relaySlice = (range, index, count) => {
  const ports = range ?? DEFAULT_RELAY_PORTS;
  const first = ports[0];
  const last = ports[1];
  const total = last - first + 1;
  const countOk = Number.isInteger(count) && count >= 1 && count <= total;
  const indexOk = Number.isInteger(index) && index >= 0 && index < count;
  if (!countOk || !indexOk) throw new Error(SLICE_ERROR);
  const base = Math.floor(total / count);
  const extra = total % count;
  const width = index < extra ? base + 1 : base;
  const skipped = index * base + Math.min(index, extra);
  const start = first + skipped;
  const end = start + width - 1;
  return [start, end];
};

const withFamily = (remote) => {
  if (KNOWN_FAMILIES.includes(remote.family)) return remote;
  const version = net.isIP(remote.address);
  const inferred = version === 6 ? 'IPv6' : 'IPv4';
  return { address: remote.address, port: remote.port, family: inferred };
};

const udpClient = (socket, remote) => {
  const transport = isV4Family(remote.family) ? 'udp4' : 'udp6';
  return { socket, transport };
};

const listenService = async (source, scope) => {
  const logger = loggerOf(source, scope);
  const secret = turnSecret(source, scope);
  const server = new IceServer({ ...source, secret, console: logger });
  await server.listen();
  logger.log(server.ports);
  const stop = () => server.close();
  return { stop };
};

const provideService = (source, scope) => {
  const thread = scope.thread;
  const relayPorts = relaySlice(source.relayPorts, thread.index, thread.count);
  const secret = turnSecret(source, scope);
  const logger = loggerOf(source, scope);
  const options = { ...source, relayPorts, secret, console: logger };
  const server = new IceServer(options);
  server.schedule();
  const warnFailure = () => {
    logger.warn('ICE UDP request failed');
  };
  const stop = () => server.close();
  const connection = (socket, info) => {
    const transport = info.tls ? 'tls' : 'tcp';
    server.accept(socket, transport);
    if (!socket.destroyed) socket.resume();
  };
  const datagram = (buffer, remote, socket) => {
    const addressed = withFamily(remote);
    const client = udpClient(socket, addressed);
    const pending = server.receive(client, buffer, addressed);
    return pending.catch(warnFailure);
  };
  return { connection, datagram, stop };
};

const start = async (options, context) => {
  const provided = options ?? {};
  const source = { ...provided };
  const scope = context ?? {};
  const thread = scope.thread ?? null;
  if (thread === null) return listenService(source, scope);
  if (typeof thread !== 'object') throw new Error(SLICE_ERROR);
  return provideService(source, scope);
};

module.exports = { relaySlice, start };
