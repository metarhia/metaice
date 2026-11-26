#!/usr/bin/env node
'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');

const { start } = require('../metaice.js');

const READERS = {
  '.json': async (file) => {
    const text = await fs.readFile(file, 'utf8');
    return JSON.parse(text);
  },
  '.js': (file) => require(file),
};

const isPlainObject = (value) => {
  if (typeof value !== 'object' || value === null) return false;
  if (Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  const isObject = prototype === Object.prototype;
  return isObject || prototype === null;
};

const readConfig = (file) => {
  const extension = path.extname(file);
  const read = READERS[extension];
  if (!read) throw new Error(`Unsupported config: ${file}`);
  const absolute = path.resolve(file);
  return read(absolute);
};

const loadOptions = () => {
  if (process.argv.length > 3) throw new Error('Unexpected argument');
  const file = process.argv[2];
  if (!file) return {};
  return readConfig(file);
};

const fail = (error) => {
  console.error(error);
  process.exit(1);
};

const main = async () => {
  const options = await loadOptions();
  if (!isPlainObject(options)) {
    throw new Error('Config must export a plain object');
  }
  let service = null;
  let isStopping = false;
  const stop = async () => {
    try {
      await service.stop();
      process.exit(0);
    } catch (error) {
      fail(error);
    }
  };
  const shutdown = () => {
    if (isStopping) return;
    isStopping = true;
    if (service) return void stop();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  const context = { name: 'metaice', console, mode: '' };
  service = await start(options, context);
  if (isStopping) await stop();
};

main().catch(fail);
