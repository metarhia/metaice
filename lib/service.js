'use strict';

const net = require('node:net');

const { IceServer } = require('./server.js');

const DEFAULT_RELAY_PORTS = [49160, 49359];
const TURN_PROTOCOL = 'stun.turn';
const SLICE_ERROR = 'Invalid relay thread or port range';

const loggerOf = (source, scope) =>
  scope.console ?? source.console ?? globalThis.console;

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
  const family = remote.family;
  const isV4 = family === 'IPv4' || family === 4;
  const isV6 = family === 'IPv6' || family === 6;
  if (isV4 || isV6) return remote;
  const version = net.isIP(remote.address);
  const inferred = version === 6 ? 'IPv6' : 'IPv4';
  return { address: remote.address, port: remote.port, family: inferred };
};

const udpClient = (socket, remote) => {
  const isV6 = remote.family === 'IPv6' || remote.family === 6;
  const transport = isV6 ? 'udp6' : 'udp4';
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

module.exports = { start, relaySlice };
