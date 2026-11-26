'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const path = require('node:path');
const { test } = require('node:test');

const { start } = require('../metaice.js');
const { createLogger, waitTcpFree } = require('./turn-helpers.js');

const EXIT_MS = 4000;

const readPorts = (logs) => {
  const ports = logs.find((entry) => entry && typeof entry.tcp === 'number');
  assert.ok(ports);
  return ports;
};

const waitForExit = async (child) => {
  const timer = setTimeout(() => {
    child.kill('SIGKILL');
  }, EXIT_MS);
  const result = await once(child, 'close');
  clearTimeout(timer);
  return result[0];
};

test('requiring metaice opens nothing', async () => {
  const root = path.join(__dirname, '..');
  const extra = path.join(root, '..');
  const current = process.env.NODE_PATH;
  const nodePath = current ? `${extra}${path.delimiter}${current}` : extra;
  const moduleName = 'metaice';
  const expression = `require('${moduleName}')`;
  const child = spawn(process.execPath, ['-e', expression], {
    cwd: root,
    env: { ...process.env, NODE_PATH: nodePath },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let errors = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    errors += chunk;
  });
  const code = await waitForExit(child);
  assert.equal(code, 0, errors);
});

test('start prefers context.console and frees the port', async () => {
  const used = [];
  const ignored = [];
  const handle = await start(
    {
      port: 0,
      listen: '127.0.0.1',
      secret: '',
      console: createLogger(ignored),
    },
    { name: 'metaice', console: createLogger(used), mode: 'test' },
  );
  const ports = readPorts(used);
  assert.deepEqual(Object.keys(handle), ['stop']);
  assert.equal(ignored.length, 0);
  assert.equal(ports.udp, ports.tcp);
  assert.equal(ports.tls, 0);
  assert.ok(ports.tcp > 0);
  const port = ports.tcp;
  const stopping = handle.stop();
  assert.equal(typeof stopping.then, 'function');
  await stopping;
  await waitTcpFree(port);
});

test('start keeps options.console when context has no console', async () => {
  const logs = [];
  const handle = await start(
    {
      port: 0,
      listen: '127.0.0.1',
      secret: '',
      console: createLogger(logs),
    },
    { name: 'metaice', mode: 'test' },
  );
  const ports = readPorts(logs);
  const port = ports.tcp;
  assert.ok(port > 0);
  await handle.stop();
  await waitTcpFree(port);
});

test('start uses options.console when context is missing', async () => {
  const logs = [];
  const handle = await start({
    port: 0,
    listen: '127.0.0.1',
    secret: '',
    console: createLogger(logs),
  });
  const ports = readPorts(logs);
  const port = ports.tcp;
  assert.ok(port > 0);
  await handle.stop();
  await waitTcpFree(port);
});
