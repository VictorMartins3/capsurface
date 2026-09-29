'use strict';

const { createHash } = require('crypto');
const MAX_BYTES = 8 * 1024 * 1024;
const MAX_ENTRIES = 128;
const entries = new Map();
let bytes = 0;
function cacheKey(input) {
  const { RULES_VERSION } = require('./rules-version');
  return createHash('sha256').update(JSON.stringify([RULES_VERSION, input.identity, input.sourceType, input.file, input.code])).digest('hex');
}
function get(key) {
  const item = entries.get(key);
  if (!item) return null;
  entries.delete(key); entries.set(key, item);
  return JSON.parse(item.text);
}
function put(key, result) {
  if (!result.parsed) return;
  const text = JSON.stringify(result), size = Buffer.byteLength(text);
  if (size > MAX_BYTES / 4) return;
  if (entries.has(key)) { bytes -= entries.get(key).size; entries.delete(key); }
  while (entries.size && (bytes + size > MAX_BYTES || entries.size >= MAX_ENTRIES)) {
    const first = entries.keys().next().value; bytes -= entries.get(first).size; entries.delete(first);
  }
  entries.set(key, { text, size }); bytes += size;
}
function clear() { entries.clear(); bytes = 0; }
module.exports = { cacheKey, get, put, clear };
