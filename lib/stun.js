'use strict';

const crypto = require('node:crypto');
const zlib = require('node:zlib');

const COOKIE = 0x2112a442;
const HEADER_SIZE = 20;
const FINGERPRINT_XOR = 0x5354554e;
const INTEGRITY_SIZE = 24;
const FINGERPRINT_SIZE = 8;
const CLASSES = ['request', 'indication', 'success', 'error'];

const METHODS = {
  binding: 0x001,
  allocate: 0x003,
  refresh: 0x004,
  send: 0x006,
  data: 0x007,
  createPermission: 0x008,
  channelBind: 0x009,
};

const ATTRIBUTES = {
  mappedAddress: 0x0001,
  username: 0x0006,
  messageIntegrity: 0x0008,
  errorCode: 0x0009,
  unknownAttributes: 0x000a,
  channelNumber: 0x000c,
  lifetime: 0x000d,
  xorPeerAddress: 0x0012,
  data: 0x0013,
  realm: 0x0014,
  nonce: 0x0015,
  xorRelayedAddress: 0x0016,
  requestedTransport: 0x0019,
  xorMappedAddress: 0x0020,
  software: 0x8022,
  fingerprint: 0x8028,
};

const typeOf = (method, kind) => {
  const index = CLASSES.indexOf(kind);
  const low = method & 0x000f;
  const middle = (method & 0x0070) << 1;
  const high = (method & 0x0f80) << 2;
  const lowBit = (index & 1) << 4;
  const highBit = (index & 2) << 7;
  return low | middle | high | lowBit | highBit;
};

const methodOf = (type) => {
  const low = type & 0x000f;
  const middle = (type >> 1) & 0x0070;
  const high = (type >> 2) & 0x0f80;
  return low | middle | high;
};

const classOf = (type) => {
  const index = ((type >> 7) & 0x2) | ((type >> 4) & 0x1);
  return CLASSES[index];
};

const isStun = (buffer) => {
  if (buffer.length < HEADER_SIZE) return false;
  const isZeroTop = (buffer[0] & 0xc0) === 0;
  return isZeroTop && buffer.readUInt32BE(4) === COOKIE;
};

const decode = (buffer) => {
  if (!isStun(buffer)) return null;
  const length = buffer.readUInt16BE(2);
  const end = HEADER_SIZE + length;
  if (length % 4 !== 0 || end > buffer.length) return null;
  const type = buffer.readUInt16BE(0);
  const transactionId = buffer.subarray(8, HEADER_SIZE);
  const attributes = [];
  let offset = HEADER_SIZE;
  while (offset + 4 <= end) {
    const size = buffer.readUInt16BE(offset + 2);
    const start = offset + 4;
    if (start + size > end) return null;
    const value = buffer.subarray(start, start + size);
    const attribute = { type: buffer.readUInt16BE(offset), value, offset };
    attributes.push(attribute);
    offset = start + Math.ceil(size / 4) * 4;
  }
  const method = methodOf(type);
  const kind = classOf(type);
  return { type, method, kind, length, transactionId, attributes };
};

const find = (message, type) => {
  const { attributes } = message;
  let index = -1;
  for (let i = 0; i < attributes.length; i++) {
    const entry = attributes[i];
    if (entry.type !== type) continue;
    index = i;
    break;
  }
  const missing = index < 0;
  const found = missing ? undefined : attributes[index];
  return found;
};

const attribute = (type, value) => {
  const padding = (4 - (value.length % 4)) % 4;
  const header = Buffer.alloc(4);
  header.writeUInt16BE(type, 0);
  header.writeUInt16BE(value.length, 2);
  return Buffer.concat([header, value, Buffer.alloc(padding)]);
};

const header = (type, length, transactionId) => {
  const bytes = Buffer.alloc(HEADER_SIZE);
  bytes.writeUInt16BE(type, 0);
  bytes.writeUInt16BE(length, 2);
  bytes.writeUInt32BE(COOKIE, 4);
  transactionId.copy(bytes, 8);
  return bytes;
};

const hmac = (key, data) => {
  const hash = crypto.createHmac('sha1', key);
  return hash.update(data).digest();
};

const crc = (data) => {
  const value = Buffer.alloc(4);
  const checksum = zlib.crc32(data) ^ FINGERPRINT_XOR;
  value.writeUInt32BE(checksum >>> 0, 0);
  return value;
};

const encode = ({ type, transactionId, attributes, key, fingerprint }) => {
  const parts = [];
  for (let i = 0; i < attributes.length; i++) {
    const entry = attributes[i];
    parts.push(attribute(entry.type, entry.value));
  }
  let body = Buffer.concat(parts);
  if (key) {
    const length = body.length + INTEGRITY_SIZE;
    const head = header(type, length, transactionId);
    const signature = hmac(key, Buffer.concat([head, body]));
    const integrity = ATTRIBUTES.messageIntegrity;
    body = Buffer.concat([body, attribute(integrity, signature)]);
  }
  if (fingerprint) {
    const length = body.length + FINGERPRINT_SIZE;
    const head = header(type, length, transactionId);
    const checksum = crc(Buffer.concat([head, body]));
    const name = ATTRIBUTES.fingerprint;
    body = Buffer.concat([body, attribute(name, checksum)]);
  }
  const head = header(type, body.length, transactionId);
  return Buffer.concat([head, body]);
};

const verifyIntegrity = (buffer, message, key) => {
  const integrity = ATTRIBUTES.messageIntegrity;
  const attribute = find(message, integrity);
  if (!attribute || attribute.value.length !== 20) return false;
  const signed = Buffer.from(buffer.subarray(0, attribute.offset));
  const length = attribute.offset + INTEGRITY_SIZE;
  signed.writeUInt16BE(length - HEADER_SIZE, 2);
  const expected = hmac(key, signed);
  return crypto.timingSafeEqual(expected, attribute.value);
};

const verifyFingerprint = (buffer, message) => {
  const name = ATTRIBUTES.fingerprint;
  const last = message.attributes.at(-1);
  if (last?.type !== name || last.value.length !== 4) return false;
  const expected = crc(buffer.subarray(0, last.offset));
  return expected.equals(last.value);
};

const longTermKey = (username, realm, password) => {
  const text = `${username}:${realm}:${password}`;
  return crypto.createHash('md5').update(text).digest();
};

const parseV4 = (address) => Buffer.from(address.split('.').map(Number));

const parseV6 = (address) => {
  const halves = address.split('::');
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  const zeros = new Array(missing).fill('0');
  const groups = halves.length > 1 ? head.concat(zeros, tail) : head;
  const bytes = Buffer.alloc(16);
  for (let i = 0; i < groups.length; i++) {
    bytes.writeUInt16BE(parseInt(groups[i], 16), i * 2);
  }
  return bytes;
};

const formatV6 = (bytes) => {
  const groups = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(bytes.readUInt16BE(i).toString(16));
  }
  return groups.join(':');
};

const readAddress = (value, transactionId) => {
  const isV4 = value[1] === 0x01;
  const port = value.readUInt16BE(2) ^ (COOKIE >>> 16);
  const mask = Buffer.alloc(16);
  mask.writeUInt32BE(COOKIE, 0);
  transactionId.copy(mask, 4);
  const size = isV4 ? 4 : 16;
  const bytes = Buffer.alloc(size);
  for (let i = 0; i < size; i++) bytes[i] = value[4 + i] ^ mask[i];
  const family = isV4 ? 'IPv4' : 'IPv6';
  const address = isV4 ? bytes.join('.') : formatV6(bytes);
  return { family, address, port };
};

const writeAddress = ({ family, address, port }, transactionId) => {
  const isV4 = family === 'IPv4';
  const bytes = isV4 ? parseV4(address) : parseV6(address);
  const value = Buffer.alloc(4 + bytes.length);
  value[1] = isV4 ? 0x01 : 0x02;
  value.writeUInt16BE(port ^ (COOKIE >>> 16), 2);
  const mask = Buffer.alloc(16);
  mask.writeUInt32BE(COOKIE, 0);
  transactionId.copy(mask, 4);
  for (let i = 0; i < bytes.length; i++) value[4 + i] = bytes[i] ^ mask[i];
  return value;
};

const errorCode = (code, reason) => {
  const text = Buffer.from(reason);
  const value = Buffer.alloc(4 + text.length);
  value[2] = Math.floor(code / 100);
  value[3] = code % 100;
  text.copy(value, 4);
  return value;
};

module.exports = {
  COOKIE,
  HEADER_SIZE,
  FINGERPRINT_XOR,
  INTEGRITY_SIZE,
  FINGERPRINT_SIZE,
  CLASSES,
  METHODS,
  ATTRIBUTES,
  typeOf,
  methodOf,
  classOf,
  isStun,
  decode,
  find,
  attribute,
  header,
  hmac,
  crc,
  encode,
  verifyIntegrity,
  verifyFingerprint,
  longTermKey,
  parseV4,
  parseV6,
  formatV6,
  readAddress,
  writeAddress,
  errorCode,
};
