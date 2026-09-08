'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const CLI = path.join(__dirname, '..', 'bin', 'capsurface.js');

function mkTmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `capsurface-test-${prefix}-`));
}

function writeFiles(baseDir, files) {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(baseDir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
}

/** Write a package.json + source files under baseDir/relDir. */
function writePackage(baseDir, relDir, pkgJson, files = {}) {
  const dir = path.join(baseDir, relDir);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkgJson, null, 2));
  writeFiles(dir, files);
  return dir;
}

/**
 * Run the CLI, returning {status, stdout, stderr} regardless of exit code.
 * Uses spawnSync rather than execFileSync: execFileSync only returns stdout
 * on a successful (zero-exit) run and discards stderr entirely in that
 * case, which silently hid a real assertion target (this tool prints
 * warnings, such as the symlink-escape warning, to stderr on an otherwise
 * successful exit 0 run).
 */
function runCli(args, opts = {}) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    ...opts,
  });
  return { status: result.status, stdout: result.stdout || '', stderr: result.stderr || '' };
}

module.exports = { mkTmpDir, writeFiles, writePackage, runCli, CLI };
