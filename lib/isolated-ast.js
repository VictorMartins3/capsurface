'use strict';

const { spawnSync } = require('child_process');
const path = require('path');

const TIMEOUT_MS = 5000;
const MAX_SOURCE = 1024 * 1024;
const failure = (reason) => ({ parsed: false, references: [{ line: 1, reason }] });

// Run only our parser helper, never the inspected file. A separate process
// lets the OS interrupt synchronous parsing, including work inside one token.
function isolatedAst(code, file, sourceType, identity) {
  if (Buffer.byteLength(code) > MAX_SOURCE) return failure('ast-source-limit');
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (['NODE_OPTIONS', 'NODE_PATH'].includes(key.toUpperCase())) delete env[key];
  }
  const child = spawnSync(process.execPath, ['--max-old-space-size=256', path.join(__dirname, 'ast-worker.js')], {
    input: JSON.stringify({ code, file, sourceType, identity }), encoding: 'utf8',
    cwd: __dirname, env, timeout: TIMEOUT_MS, killSignal: 'SIGKILL',
    maxBuffer: 16 * 1024 * 1024, windowsHide: true,
  });
  if (child.error && child.error.code === 'ETIMEDOUT') return failure('ast-timeout');
  if (child.error || child.status !== 0 || child.signal) return failure('ast-worker-error');
  try {
    const result = JSON.parse(child.stdout);
    if (typeof result.parsed !== 'boolean' || !Array.isArray(result.references) ||
        (!result.parsed && !result.references.length)) return failure('ast-worker-error');
    return result;
  } catch (_) { return failure('ast-worker-error'); }
}

module.exports = { isolatedAst, TIMEOUT_MS };
