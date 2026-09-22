'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SCOPE = 'package-files-v1';
const MAX_FILES = 100000;
const MAX_BYTES = 1024 * 1024 * 1024;

function validIntegrity(value) {
  return !!value && value.complete === true && value.algorithm === 'sha256' &&
    value.scope === SCOPE && typeof value.digest === 'string' && /^[a-f0-9]{64}$/.test(value.digest);
}

// Hash installed bytes, including non-source files. Dependencies and Git
// metadata are separate inputs. Never follow package-internal symlinks: their
// target bytes would otherwise escape this content boundary.
function contentIntegrity(root) {
  const hash = crypto.createHash('sha256').update(SCOPE + '\0');
  const buffer = Buffer.alloc(64 * 1024);
  let files = 0;
  let bytes = 0;
  let entries = 0;
  let current = '.';
  function walk(dir, relative, depth) {
    if (depth > 128) throw new Error('directory depth exceeds content budget');
    for (const name of fs.readdirSync(dir).sort()) {
      current = relative ? `${relative}/${name}` : name;
      if (++entries > MAX_FILES) throw new Error('entry count exceeds content budget');
      const full = path.join(dir, name);
      const stat = fs.lstatSync(full);
      if (stat.isDirectory()) {
        if (name !== 'node_modules' && name !== '.git') walk(full, current, depth + 1);
        continue;
      }
      if (!stat.isFile()) throw new Error('non-regular file is outside the supported content scope');
      if (bytes + stat.size > MAX_BYTES) throw new Error('package exceeds content byte budget');
      // Length-prefixed metadata separates filenames, sizes and contents.
      const header = JSON.stringify([current, stat.size]);
      hash.update(String(Buffer.byteLength(header)) + ':').update(header);
      let fd;
      try {
        fd = fs.openSync(full, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
        const opened = fs.fstatSync(fd);
        if (!opened.isFile() || opened.dev !== stat.dev || opened.ino !== stat.ino || opened.size !== stat.size) {
          throw new Error('file changed while opening');
        }
        let offset = 0;
        while (offset < stat.size) {
          const count = fs.readSync(fd, buffer, 0, Math.min(buffer.length, stat.size - offset), offset);
          if (!count) throw new Error('file changed while hashing');
          hash.update(buffer.subarray(0, count));
          offset += count;
        }
        const after = fs.fstatSync(fd);
        if (after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs) {
          throw new Error('file changed while hashing');
        }
        files++;
        bytes += offset;
      } finally {
        if (fd !== undefined) fs.closeSync(fd);
      }
    }
  }
  try {
    walk(root, '', 0);
    return { algorithm: 'sha256', scope: SCOPE, complete: true, digest: hash.digest('hex'), files, bytes };
  } catch (error) {
    return { algorithm: 'sha256', scope: SCOPE, complete: false, files, bytes,
      error: { file: current, reason: error.code || error.message } };
  }
}

module.exports = { contentIntegrity, validIntegrity };
