'use strict';

const { spawnSync } = require('child_process');
const path = require('path');

const TIMEOUT_MS = 5000;
const MAX_SOURCE = 1024 * 1024;
const MAX_OUTPUT = 16 * 1024 * 1024;
const failure = (reason) => ({ parsed: false, references: [{ line: 1, reason }] });
const validResult = (result) => result && typeof result.parsed === 'boolean' && Array.isArray(result.references)
  && (result.parsed || result.references.length > 0);
function workerEnvironment() {
  return Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    ['PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'].includes(key.toUpperCase())));
}

// Run only our parser helper, never the inspected file. A separate process
// lets the OS interrupt synchronous parsing, including work inside one token.
function isolatedAst(code, file, sourceType, identity) {
  if (Buffer.byteLength(code) > MAX_SOURCE) return failure('ast-source-limit');
  const env = workerEnvironment();
  const child = spawnSync(process.execPath, ['--max-old-space-size=256', path.join(__dirname, 'ast-worker.js')], {
    input: JSON.stringify({ code, file, sourceType, identity }), encoding: 'utf8',
    cwd: __dirname, env, timeout: TIMEOUT_MS, killSignal: 'SIGKILL',
    maxBuffer: MAX_OUTPUT, windowsHide: true,
  });
  if (child.error && child.error.code === 'ETIMEDOUT') return failure('ast-timeout');
  if (child.error || child.status !== 0 || child.signal) return failure('ast-worker-error');
  try {
    const result = JSON.parse(child.stdout);
    if (!validResult(result)) return failure('ast-worker-error');
    return result;
  } catch (_) { return failure('ast-worker-error'); }
}

function isolatedBatch(inputs) {
  if (!inputs.length) return [];
  if (inputs.length === 1) {
    const { code, file, sourceType, identity } = inputs[0];
    return [isolatedAst(code, file, sourceType, identity)];
  }
  if (inputs.length > 64 || inputs.some((i) => Buffer.byteLength(i.code) > MAX_SOURCE)) return inputs.map(() => failure('ast-source-limit'));
  const input = JSON.stringify(inputs);
  if (Buffer.byteLength(input) > 16 * 1024 * 1024) return inputs.map(() => failure('ast-source-limit'));
  const child = spawnSync(process.execPath, [path.join(__dirname, 'ast-batch-worker.js')], {
    input, encoding: 'utf8', cwd: __dirname, env: workerEnvironment(),
    detached: process.platform !== 'win32',
    timeout: inputs.length * TIMEOUT_MS + 10000, killSignal: 'SIGKILL', maxBuffer: MAX_OUTPUT, windowsHide: true,
  });
  if (child.error || child.status !== 0 || child.signal) {
    // The supervisor normally reaps its parser. Clean up its process group if
    // the supervisor itself failed or exceeded the outer deadline.
    if (child.pid && process.platform !== 'win32') {
      try { process.kill(-child.pid, 'SIGKILL'); } catch (_) { /* already reaped */ }
    }
    return inputs.map(() => failure('ast-worker-error'));
  }
  try {
    const results = JSON.parse(child.stdout);
    return Array.isArray(results) && results.length === inputs.length && results.every(validResult)
      ? results : inputs.map(() => failure('ast-worker-error'));
  } catch (_) { return inputs.map(() => failure('ast-worker-error')); }
}

module.exports = { isolatedAst, isolatedBatch, TIMEOUT_MS, MAX_OUTPUT, validResult, workerEnvironment };
