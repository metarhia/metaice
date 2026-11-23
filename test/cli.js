'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const dgram = require('node:dgram');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const timers = require('node:timers/promises');

const { stun } = require('../metaice.js');

const delay = timers.setTimeout;
const root = path.join(__dirname, '..');
const bin = path.join(root, 'bin', 'metaice.js');
const REPLY_MS = 300;
const READY_MS = 5000;
const EXIT_MS = 5000;

const reservePort = () =>
  new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = address.port;
      server.close((error) => {
        if (error) reject(error);
        else resolve(port);
      });
    });
  });

const holdPort = () =>
  new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      resolve(server);
    });
  });

const closeServer = (server) =>
  new Promise((resolve, reject) => {
    server.close((error) => {
      if (error && error.code !== 'ERR_SERVER_NOT_RUNNING') reject(error);
      else resolve();
    });
  });

const listenTcp = (port) =>
  new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen({ port, host: '127.0.0.1' }, () => {
      server.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  });

const bindTcp = async (port) => {
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

const closeUdp = (socket) =>
  new Promise((resolve, reject) => {
    try {
      socket.close(resolve);
    } catch (error) {
      if (error.code === 'ERR_SOCKET_DGRAM_NOT_RUNNING') resolve();
      else reject(error);
    }
  });

const bindUdp = (socket) =>
  new Promise((resolve, reject) => {
    let onError = null;
    let onListening = null;
    onError = (error) => {
      socket.off('listening', onListening);
      reject(error);
    };
    onListening = () => {
      socket.off('error', onError);
      resolve();
    };
    socket.once('error', onError);
    socket.once('listening', onListening);
    socket.bind(0, '127.0.0.1');
  });

const binding = () => {
  const type = stun.typeOf(stun.METHODS.binding, 'request');
  const transactionId = crypto.randomBytes(12);
  return stun.encode({
    type,
    transactionId,
    attributes: [],
    fingerprint: true,
  });
};

const sendBinding = (socket, port, packet) =>
  new Promise((resolve, reject) => {
    let isDone = false;
    let cleanup = null;
    const finish = (settle, value) => {
      if (isDone) return;
      isDone = true;
      cleanup();
      settle(value);
    };
    const onMessage = (buffer) => {
      finish(resolve, buffer);
    };
    const onError = (error) => {
      finish(reject, error);
    };
    const timer = setTimeout(() => {
      onError(new Error('No STUN reply'));
    }, REPLY_MS);
    cleanup = () => {
      clearTimeout(timer);
      socket.off('message', onMessage);
      socket.off('error', onError);
    };
    socket.once('message', onMessage);
    socket.once('error', onError);
    socket.send(packet, port, '127.0.0.1', (error) => {
      if (error) onError(error);
    });
  });

const waitForBinding = async (socket, port, packet) => {
  const deadline = Date.now() + READY_MS;
  let failure = new Error('No STUN reply');
  while (Date.now() < deadline) {
    try {
      return await sendBinding(socket, port, packet);
    } catch (error) {
      failure = error;
      await delay(30);
    }
  }
  throw failure;
};

const collect = (stream) => {
  let text = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk) => {
    text += chunk;
  });
  return () => text;
};

const spawnCli = (t, file, ipc = false) => {
  const stdio = ['ignore', 'pipe', 'pipe'];
  if (ipc) stdio.push('ipc');
  const child = spawn(process.execPath, [bin, file], {
    cwd: root,
    env: { ...process.env, FORCE_COLOR: '0', NO_COLOR: '1' },
    stdio,
  });
  const output = collect(child.stdout);
  const errors = collect(child.stderr);
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
    }
  });
  return { child, output, errors };
};

const waitForCode = async (child) => {
  const timer = setTimeout(() => {
    child.kill('SIGKILL');
  }, EXIT_MS);
  try {
    const [code] = await once(child, 'close');
    return code;
  } finally {
    clearTimeout(timer);
  }
};

const configPath = (port, extension) =>
  path.join(os.tmpdir(), `metaice-${process.pid}-${port}${extension}`);

test('CLI', async (t) => {
  await t.test('answers Binding and shuts down cleanly', async (t) => {
    const port = await reservePort();
    const file = configPath(port, '.js');
    const jsString = (value) => `'${value}'`;
    const isWindows = process.platform === 'win32';
    // kill('SIGTERM') force-terminates child processes on Windows.
    const onMessage =
      `process.once(${jsString('message')}, ` +
      `() => process.emit(${jsString('SIGTERM')}));`;
    const setup = isWindows ? [onMessage, ''] : [];
    const source = [
      `${jsString('use strict')};`,
      '',
      ...setup,
      'module.exports = {',
      `  listen: ${jsString('127.0.0.1')},`,
      `  port: ${port},`,
      `  secret: ${jsString('')},`,
      '};',
      '',
    ].join('\n');
    await fs.writeFile(file, source);
    t.after(() => fs.rm(file, { force: true }));
    const cli = spawnCli(t, file, isWindows);
    const socket = dgram.createSocket('udp4');
    t.after(() => closeUdp(socket));
    await bindUdp(socket);
    const packet = binding();
    const reply = await waitForBinding(socket, port, packet);
    const message = stun.decode(reply);
    assert.ok(message);
    assert.equal(message.kind, 'success');
    assert.equal(message.method, stun.METHODS.binding);
    assert.equal(stun.verifyFingerprint(reply, message), true);
    const closed = waitForCode(cli.child);
    if (isWindows) cli.child.send('shutdown');
    else cli.child.kill('SIGTERM');
    const code = await closed;
    assert.equal(code, 0, cli.errors());
    assert.match(cli.output(), new RegExp(`tcp: ${port}`));
    await bindTcp(port);
  });

  await t.test('exits 1 when the port is taken', async (t) => {
    const holder = await holdPort();
    t.after(() => closeServer(holder));
    const address = holder.address();
    const port = address.port;
    const file = configPath(port, '.json');
    const source = JSON.stringify({
      listen: '127.0.0.1',
      port,
      secret: '',
    });
    await fs.writeFile(file, source);
    t.after(() => fs.rm(file, { force: true }));
    const cli = spawnCli(t, file);
    const code = await waitForCode(cli.child);
    assert.equal(code, 1);
    assert.match(cli.errors(), /EADDRINUSE/);
    await closeServer(holder);
    await bindTcp(port);
  });
});
