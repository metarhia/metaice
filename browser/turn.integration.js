'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { setTimeout: delay } = require('node:timers/promises');

const { IceServer, iceServers } = require('../metaice.js');

const CHROME = process.env.CHROME_BIN ?? '/usr/bin/google-chrome';
const SECRET = 'browser-turn-secret';
const COMMAND_TIMEOUT_MS = 60000;
const PAGE = [
  '<!doctype html>',
  '<meta charset="utf-8">',
  '<title>metaice</title>',
  '<script>',
  'const selectedType = async (pc) => {',
  '  const stats = await pc.getStats();',
  '  let pairId = "";',
  '  for (const report of stats.values()) {',
  '    const isTransport = report.type === "transport";',
  '    const selected = report.selectedCandidatePairId;',
  '    if (isTransport && selected) pairId = selected;',
  '  }',
  '  if (!pairId) return "";',
  '  const pair = stats.get(pairId);',
  '  if (!pair) return "";',
  '  const local = stats.get(pair.localCandidateId);',
  '  return local ? local.candidateType : "";',
  '};',
  'const gather = (pc) => new Promise((resolve, reject) => {',
  '  const timer = setTimeout(() => {',
  '    reject(new Error("ICE gathering timed out"));',
  '  }, 40000);',
  '  const done = () => {',
  '    clearTimeout(timer);',
  '    resolve();',
  '  };',
  '  if (pc.iceGatheringState === "complete") {',
  '    done();',
  '    return;',
  '  }',
  '  pc.addEventListener("icecandidate", (event) => {',
  '    if (!event.candidate) done();',
  '  });',
  '});',
  'const opened = (channel) => new Promise((resolve, reject) => {',
  '  const timer = setTimeout(() => {',
  '    reject(new Error("data channel did not open"));',
  '  }, 40000);',
  '  channel.addEventListener("open", () => {',
  '    clearTimeout(timer);',
  '    resolve();',
  '  });',
  '});',
  'globalThis.relay = async (servers) => {',
  '  const config = {',
  '    iceServers: servers,',
  '    iceTransportPolicy: "relay",',
  '  };',
  '  const left = new RTCPeerConnection(config);',
  '  const right = new RTCPeerConnection(config);',
  '  try {',
  '    const incoming = new Promise((resolve) => {',
  '      right.ondatachannel = (event) => {',
  '        event.channel.onmessage = (message) => {',
  '          resolve(message.data);',
  '        };',
  '      };',
  '    });',
  '    const channel = left.createDataChannel("relay");',
  '    const offer = await left.createOffer();',
  '    await left.setLocalDescription(offer);',
  '    await gather(left);',
  '    if (!left.localDescription.sdp.includes("typ relay")) {',
  '      throw new Error("no relay candidate");',
  '    }',
  '    const remoteOffer = left.localDescription;',
  '    await right.setRemoteDescription(remoteOffer);',
  '    const answer = await right.createAnswer();',
  '    await right.setLocalDescription(answer);',
  '    await gather(right);',
  '    if (!right.localDescription.sdp.includes("typ relay")) {',
  '      throw new Error("no relay candidate");',
  '    }',
  '    const remoteAnswer = right.localDescription;',
  '    await left.setRemoteDescription(remoteAnswer);',
  '    await opened(channel);',
  '    channel.send("relay-ok");',
  '    const received = await incoming;',
  '    const leftType = await selectedType(left);',
  '    const rightType = await selectedType(right);',
  '    return { received, leftType, rightType };',
  '  } finally {',
  '    left.close();',
  '    right.close();',
  '  }',
  '};',
  '</script>',
].join('\n');

const turnEntry = (list, transport) => {
  const turn = list[1];
  const suffix = `transport=${transport}`;
  let url = '';
  for (let i = 0; i < turn.urls.length; i++) {
    const candidate = turn.urls[i];
    if (candidate.includes(suffix)) url = candidate;
  }
  return {
    urls: [url],
    username: turn.username,
    credential: turn.credential,
  };
};

const readEndpoint = async (profile) => {
  const file = path.join(profile, 'DevToolsActivePort');
  const text = await fs.readFile(file, 'utf8');
  const lines = text.trim().split('\n');
  const port = lines[0];
  const route = lines[1];
  return `ws://127.0.0.1:${port}${route}`;
};

const waitForEndpoint = async (profile, chrome) => {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (chrome.exitCode !== null) return '';
    try {
      return await readEndpoint(profile);
    } catch {
      await delay(100);
    }
  }
  return '';
};

const stopChrome = async (chrome) => {
  if (!chrome || chrome.exitCode !== null) return;
  chrome.kill();
  await Promise.race([once(chrome, 'exit'), delay(2000)]);
  if (chrome.exitCode === null) chrome.kill('SIGKILL');
};

const closeServer = (server) =>
  new Promise((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  });

const runRelay = (browser, sessionId, list, transport) => {
  const entry = turnEntry(list, transport);
  const url = entry.urls[0];
  assert.equal(url.includes('127.0.0.1'), true);
  const marker = `transport=${transport}`;
  assert.equal(url.includes(marker), true);
  const expression = `relay(${JSON.stringify([entry])})`;
  return browser.evaluate(sessionId, expression);
};

const assertRelay = (result) => {
  assert.equal(result.received, 'relay-ok');
  assert.equal(result.leftType, 'relay');
  assert.equal(result.rightType, 'relay');
};

class BrowserSession {
  constructor(socket) {
    this.socket = socket;
    this.id = 0;
    this.pending = new Map();
    socket.addEventListener('message', (event) => {
      this.onMessage(event.data);
    });
  }

  onMessage(data) {
    const message = JSON.parse(data);
    if (!message.id) return;
    const request = this.pending.get(message.id);
    if (!request) return;
    this.pending.delete(message.id);
    clearTimeout(request.timer);
    if (message.error) {
      request.reject(new Error(JSON.stringify(message.error)));
      return;
    }
    request.resolve(message.result);
  }

  request(method, params = {}, sessionId = '') {
    const id = ++this.id;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        const reason = `Browser command timed out: ${method}`;
        reject(new Error(reason));
      }, COMMAND_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.send(JSON.stringify(payload));
    });
  }

  async openPage(url) {
    const created = await this.request('Target.createTarget', { url });
    const targetId = created.targetId;
    const attached = await this.request('Target.attachToTarget', {
      targetId,
      flatten: true,
    });
    const sessionId = attached.sessionId;
    await this.request('Runtime.enable', {}, sessionId);
    await this.wait(sessionId, 'Boolean(globalThis.relay)');
    return sessionId;
  }

  async evaluate(sessionId, expression) {
    const params = {
      expression,
      awaitPromise: true,
      returnByValue: true,
    };
    const result = await this.request('Runtime.evaluate', params, sessionId);
    if (result.exceptionDetails) {
      const details = result.exceptionDetails;
      const description = details.exception && details.exception.description;
      throw new Error(description || JSON.stringify(details));
    }
    return result.result.value;
  }

  async wait(sessionId, expression) {
    for (let attempt = 0; attempt < 100; attempt++) {
      const ready = await this.evaluate(sessionId, expression);
      if (ready) return;
      await delay(100);
    }
    const reason = `Browser condition timed out: ${expression}`;
    throw new Error(reason);
  }

  close() {
    for (const request of this.pending.values()) {
      clearTimeout(request.timer);
      request.reject(new Error('Browser closed'));
    }
    this.pending.clear();
    this.socket.close();
  }
}

test(
  'Chrome relay data channel over TURN UDP then TCP',
  { timeout: 120000 },
  async (t) => {
    let browser = null;
    let chrome = null;
    let profile = '';
    let diagnostics = '';
    const ice = new IceServer({
      listen: '127.0.0.1',
      publicAddress: '127.0.0.1',
      allowPrivatePeers: true,
      port: 0,
      secret: SECRET,
    });
    const server = http.createServer((req, res) => {
      const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
      if (pathname !== '/') {
        res.writeHead(404);
        return void res.end();
      }
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      res.end(PAGE);
    });
    t.after(async () => {
      if (browser) browser.close();
      await stopChrome(chrome);
      await ice.close();
      await closeServer(server);
      if (!profile) return;
      await fs.rm(profile, {
        recursive: true,
        force: true,
        maxRetries: 5,
        retryDelay: 200,
      });
    });
    await ice.listen();
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const origin = `http://127.0.0.1:${server.address().port}`;
    profile = await fs.mkdtemp(path.join(os.tmpdir(), 'metaice-turn-'));
    chrome = spawn(
      CHROME,
      [
        '--headless=new',
        '--no-sandbox',
        '--disable-gpu',
        '--no-first-run',
        '--no-default-browser-check',
        '--allow-loopback-in-peer-connection',
        '--remote-debugging-port=0',
        `--user-data-dir=${profile}`,
        'about:blank',
      ],
      { stdio: ['ignore', 'ignore', 'pipe'] },
    );
    chrome.stderr.on('data', (data) => {
      diagnostics += data.toString();
      if (diagnostics.length > 4000) diagnostics = diagnostics.slice(-4000);
    });
    chrome.on('error', (error) => {
      diagnostics += error.message;
    });
    const endpoint = await waitForEndpoint(profile, chrome);
    const failure = `Chrome did not start: ${diagnostics}`;
    assert.ok(endpoint, failure);
    const socket = new WebSocket(endpoint);
    await new Promise((resolve, reject) => {
      socket.addEventListener('open', () => resolve(), { once: true });
      socket.addEventListener(
        'error',
        () => reject(new Error('Chrome DevTools socket failed')),
        { once: true },
      );
    });
    browser = new BrowserSession(socket);
    const version = await browser.request('Browser.getVersion');
    console.log(`Verified browser: ${version.product}`);
    const list = iceServers({
      name: '127.0.0.1',
      port: ice.ports.udp,
      secret: SECRET,
      peer: 'chrome',
    });
    assert.equal(list.length, 2);
    const sessionId = await browser.openPage(`${origin}/`);
    const udp = await runRelay(browser, sessionId, list, 'udp');
    assertRelay(udp);
    const tcp = await runRelay(browser, sessionId, list, 'tcp');
    assertRelay(tcp);
  },
);
