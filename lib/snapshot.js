'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const INDEX = '.capsurface-snapshot';
const LOCK = '.capsurface-write.lock';
const digest = (text) => crypto.createHash('sha256').update(text).digest('hex');

function atomicWrite(file, text) {
  const temporary = `${file}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(temporary, text, { flag: 'wx' });
    fs.renameSync(temporary, file);
  } finally {
    try { fs.unlinkSync(temporary); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
}

// Publish the inventory last. An interrupted scan leaves an incomplete
// marker, and concurrent writers must use different output directories.
function beginSnapshot(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const lock = path.join(dir, LOCK);
  let fd;
  try {
    fd = fs.openSync(lock, 'wx');
  } catch (e) {
    if (e.code === 'EEXIST') throw new Error(`snapshot is locked: ${dir}; use a fresh output directory if an earlier scan was interrupted`);
    throw e;
  }
  fs.closeSync(fd);
  const index = path.join(dir, INDEX);
  try {
    atomicWrite(index, JSON.stringify({ schemaVersion: 1, complete: false }));
  } catch (e) {
    fs.unlinkSync(lock);
    throw e;
  }
  const entries = [];
  return {
    write(file, manifest) {
      const text = JSON.stringify(manifest, null, 2);
      atomicWrite(path.join(dir, file), text);
      entries.push({ file, sha256: digest(text) });
    },
    complete() {
      atomicWrite(index, JSON.stringify({ schemaVersion: 1, complete: true, manifests: entries }, null, 2));
    },
    close() { fs.unlinkSync(lock); },
  };
}

function readManifests(dir) {
  if (fs.existsSync(path.join(dir, LOCK))) throw new Error(`snapshot is locked: ${dir}; scan is still running or was interrupted`);
  let raw;
  try {
    raw = fs.readFileSync(path.join(dir, INDEX), 'utf8');
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    // Backwards compatibility for directories assembled with `scan --out`.
    const manifests = fs.readdirSync(dir).filter((file) => file.endsWith('.json')).map((file) =>
      JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'))
    );
    if (fs.existsSync(path.join(dir, LOCK)) || fs.existsSync(path.join(dir, INDEX))) {
      throw new Error(`snapshot changed while reading: ${dir}; retry after scan-tree finishes`);
    }
    return manifests;
  }
  const snapshot = JSON.parse(raw);
  if (snapshot.schemaVersion !== 1 || snapshot.complete !== true || !Array.isArray(snapshot.manifests)) {
    throw new Error(`incomplete or unsupported snapshot: ${dir}; run scan-tree again`);
  }
  const names = new Set();
  const manifests = snapshot.manifests.map(({ file, sha256 }) => {
    if (typeof file !== 'string' || !file.endsWith('.json') || /[/\\]/.test(file) || names.has(file)) {
      throw new Error(`invalid manifest entry in snapshot: ${dir}`);
    }
    names.add(file);
    const full = path.join(dir, file);
    if (!fs.lstatSync(full).isFile()) throw new Error(`snapshot manifest is not a regular file: ${file}`);
    const text = fs.readFileSync(full, 'utf8');
    if (digest(text) !== sha256) throw new Error(`snapshot manifest changed: ${file}; run scan-tree again`);
    return JSON.parse(text);
  });
  // A writer may have started after the initial check. Never combine two
  // generations, even when every individual manifest still parsed.
  if (fs.existsSync(path.join(dir, LOCK)) || fs.readFileSync(path.join(dir, INDEX), 'utf8') !== raw) {
    throw new Error(`snapshot changed while reading: ${dir}; retry after scan-tree finishes`);
  }
  return manifests;
}

module.exports = { beginSnapshot, readManifests };
