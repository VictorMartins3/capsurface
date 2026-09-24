'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const MAX_COMPRESSED = 64 * 1024 * 1024;
const MAX_EXPANDED = 256 * 1024 * 1024;
const MAX_ENTRIES = 100000;

function readBounded(file, limit) {
  if (!fs.lstatSync(file).isFile()) throw new Error(`expected a regular file: ${file}`);
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > limit) throw new Error(`file exceeds ${limit}-byte limit: ${file}`);
    const data = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < data.length) {
      const count = fs.readSync(fd, data, offset, data.length - offset, null);
      if (!count) throw new Error(`file changed while reading: ${file}`);
      offset += count;
    }
    if (fs.readSync(fd, Buffer.alloc(1), 0, 1, null)) throw new Error(`file changed while reading: ${file}`);
    return data;
  } finally { fs.closeSync(fd); }
}

function verifyIntegrity(data, integrity) {
  if (typeof integrity !== 'string' || !integrity.trim() || integrity.length > 8192) throw new Error('missing or invalid tarball integrity');
  const rank = { sha256: 1, sha384: 2, sha512: 3 };
  const digests = integrity.trim().split(/\s+/).map((token) => {
    const match = /^(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})$/.exec(token);
    if (!match) throw new Error('tarball integrity must use SHA-256, SHA-384 or SHA-512');
    const digest = Buffer.from(match[2], 'base64');
    if (digest.toString('base64') !== match[2] || digest.length !== Number(match[1].slice(3)) / 8) throw new Error('invalid integrity digest');
    return { algorithm: match[1], digest };
  });
  const strongest = Math.max(...digests.map((item) => rank[item.algorithm]));
  const candidates = digests.filter((item) => rank[item.algorithm] === strongest);
  const actual = crypto.createHash(candidates[0].algorithm).update(data).digest();
  if (!candidates.some((item) => crypto.timingSafeEqual(actual, item.digest))) throw new Error('tarball integrity mismatch');
  return `${candidates[0].algorithm}-${actual.toString('base64')}`;
}

function text(bytes) {
  const value = bytes.toString('utf8');
  if (!Buffer.from(value).equals(bytes)) throw new Error('invalid UTF-8 archive metadata');
  return value;
}
function field(bytes) {
  const end = bytes.indexOf(0);
  if (end !== -1 && bytes.subarray(end).some((byte) => byte !== 0)) throw new Error('invalid tar header padding');
  return text(end === -1 ? bytes : bytes.subarray(0, end));
}
function octal(bytes) {
  const value = bytes.toString('latin1').replace(/\0 *$/, '').trim();
  if (!/^[0-7]+$/.test(value)) throw new Error('unsupported tar numeric field');
  const number = parseInt(value, 8);
  if (!Number.isSafeInteger(number)) throw new Error('tar numeric field exceeds limits');
  return number;
}

function ustarPrefix(header) {
  // node-tar uses the final 24 bytes of a short prefix for atime/ctime.
  // A nonzero byte at 475 instead denotes a full POSIX 155-byte prefix.
  if (header[475] !== 0) return field(header.subarray(345, 500));
  for (const start of [476, 488]) {
    const timestamp = header.subarray(start, start + 12);
    if (timestamp.some((byte) => byte !== 0)) octal(timestamp);
  }
  return field(header.subarray(345, 475));
}
function pax(data) {
  if (data.length > 16384) throw new Error('tar metadata exceeds limit');
  const values = new Map();
  const allowed = new Set(['path', 'size', 'mtime', 'atime', 'ctime', 'uid', 'gid', 'uname', 'gname', 'charset', 'comment']);
  for (let offset = 0; offset < data.length;) {
    const space = data.indexOf(32, offset);
    const lengthText = data.subarray(offset, space).toString('latin1');
    if (space < offset || !/^[1-9][0-9]{0,6}$/.test(lengthText)) throw new Error('invalid PAX record length');
    const end = offset + Number(lengthText);
    if (end > data.length || end <= space + 1 || data[end - 1] !== 10) throw new Error('truncated PAX record');
    const record = text(data.subarray(space + 1, end - 1));
    const equals = record.indexOf('=');
    const key = record.slice(0, equals);
    if (equals < 1 || !allowed.has(key) || values.has(key)) throw new Error('unsupported or duplicate PAX attribute');
    values.set(key, record.slice(equals + 1));
    offset = end;
  }
  return values;
}

function portableComponent(part) {
  if (!part || part === '..' || /[\\:\x00-\x1f\x7f<>"|?*]/.test(part) || /[. ]$/.test(part)) return false;
  // Windows also reserves superscript COM/LPT digits and device extensions.
  const stem = part.split('.')[0].normalize('NFKC').trim();
  return !/^(con|conin\$|conout\$|prn|aux|nul|com[0-9]|lpt[0-9])$/i.test(stem);
}

// Parse and validate the entire bounded archive before writing into a fresh
// private directory. Links, special files and ambiguous portable paths fail.
function unpackTarball(file, integrity, destination, budget = {}) {
  const compressed = readBounded(file, Math.min(MAX_COMPRESSED, budget.compressed === undefined ? MAX_COMPRESSED : budget.compressed));
  const verified = verifyIntegrity(compressed, integrity);
  const data = zlib.gunzipSync(compressed, { maxOutputLength: Math.min(MAX_EXPANDED, budget.expanded === undefined ? MAX_EXPANDED : budget.expanded) });
  if (data.length % 512) throw new Error('truncated tar archive');
  const files = [];
  const paths = new Map();
  const explicit = new Map();
  let metadata = null;
  let ended = false;
  let entries = 0;
  let archiveRoot;
  for (let offset = 0; offset < data.length;) {
    const header = data.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      if (metadata || offset + 1024 > data.length || data.subarray(offset).some((byte) => byte !== 0)) throw new Error('invalid tar terminator');
      ended = true;
      break;
    }
    if (++entries > MAX_ENTRIES) throw new Error('tar entry limit exceeded');
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : header[i];
    if (sum !== octal(header.subarray(148, 156))) throw new Error('tar header checksum mismatch');
    const magic = header.subarray(257, 263).toString('latin1');
    if (magic !== 'ustar\0' && magic !== 'ustar ') throw new Error('unsupported tar header format');
    const type = header[156];
    let size = octal(header.subarray(124, 136));
    if (metadata && metadata.has('size')) {
      const value = metadata.get('size');
      if (!/^(0|[1-9][0-9]*)$/.test(value)) throw new Error('invalid PAX size');
      size = Number(value);
    }
    if (!Number.isSafeInteger(size) || size > MAX_EXPANDED || offset + 512 + size > data.length) throw new Error('tar entry exceeds available data or size limit');
    const body = data.subarray(offset + 512, offset + 512 + size);
    offset += 512 + Math.ceil(size / 512) * 512;
    if (type === 120 || type === 76) {
      if (metadata) throw new Error('stacked tar metadata is unsupported');
      if (body.length > 16384) throw new Error('tar metadata exceeds limit');
      metadata = type === 120 ? pax(body) : new Map([['path', field(body)]]);
      continue;
    }
    if (![0, 48, 53].includes(type)) throw new Error('tar links and special entries are unsupported');
    if (field(header.subarray(157, 257))) throw new Error('unexpected tar link target');
    const prefix = magic === 'ustar\0' ? ustarPrefix(header) : '';
    const name = metadata && metadata.has('path') ? metadata.get('path') : (prefix ? prefix + '/' : '') + field(header.subarray(0, 100));
    metadata = null;
    const directory = type === 53;
    if (directory && size) throw new Error('tar directory has file content');
    const slash = name.indexOf('/');
    const root = slash === -1 ? name : name.slice(0, slash);
    if (!portableComponent(root) || ['node_modules', '.git'].includes(root.toLowerCase())) throw new Error('unsafe tar archive root');
    if (archiveRoot === undefined) archiveRoot = root;
    if (root !== archiveRoot) throw new Error('tar entries must share a single archive root');
    if (directory && (name === root || name === root + '/')) continue;
    if (slash === -1) throw new Error('tar files must be below the archive root');
    const raw = directory ? name.slice(slash + 1).replace(/\/$/, '') : name.slice(slash + 1);
    const parts = raw.split('/').filter((part) => part !== '.');
    if (directory && !parts.length) continue;
    const relative = parts.join('/');
    if (!parts.length || raw.length > 4096 || parts.length > 128 || !parts.every(portableComponent)) throw new Error('unsafe or unsupported tar path');
    if (parts.some((part) => ['node_modules', '.git'].includes(part.toLowerCase()))) throw new Error('bundled dependencies and .git entries are unsupported');
    let duplicate = false;
    for (let i = 1; i <= parts.length; i++) {
      const current = parts.slice(0, i).join('/');
      const key = current.normalize('NFC').toLowerCase();
      const isDirectory = i < parts.length || directory;
      const previous = paths.get(key);
      if (previous && (previous.path !== current || previous.directory !== isDirectory)) throw new Error('ambiguous tar path or file/directory collision');
      if (i === parts.length) {
        if (explicit.has(key)) {
          if (!directory && !explicit.get(key).equals(body)) throw new Error('conflicting duplicate tar entry');
          duplicate = true;
        }
        explicit.set(key, directory ? null : body);
      }
      paths.set(key, { path: current, directory: isDirectory });
    }
    if (!directory && !duplicate) files.push({ path: relative, data: body });
  }
  if (!ended) throw new Error('missing tar terminator');
  const packageFile = files.find((item) => item.path === 'package.json');
  if (!packageFile || packageFile.data.length > 1024 * 1024) throw new Error('missing or oversized package.json');
  const pkg = JSON.parse(text(packageFile.data));
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) throw new Error('package.json must contain an object');
  if (!fs.lstatSync(destination).isDirectory() || fs.readdirSync(destination).length) throw new Error('tar destination must be empty');
  for (const item of files) {
    const target = path.join(destination, item.path);
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    fs.writeFileSync(target, item.data, { flag: 'wx', mode: 0o600 });
  }
  return { pkg, integrity: verified, compressedBytes: compressed.length, expandedBytes: data.length };
}

module.exports = { unpackTarball, readBounded, verifyIntegrity };
