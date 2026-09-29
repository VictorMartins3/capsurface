'use strict';

// This supervisor never parses target source. Its event loop can kill a parser
// stuck inside synchronous work and wait for close before serving the next file.
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { TIMEOUT_MS, MAX_OUTPUT, validResult } = require('./isolated-ast');
const failure = (reason) => ({ parsed: false, references: [{ line: 1, reason }] });

async function main() {
  const inputs = JSON.parse(fs.readFileSync(0, 'utf8'));
  if (!Array.isArray(inputs) || inputs.length > 64) throw Error('invalid batch');
  let child, pending, buffer = '', bytes = 0;
  function start() {
    child = spawn(process.execPath, ['--max-old-space-size=256', path.join(__dirname, 'ast-worker.js'), '--stream'],
      { cwd: __dirname, env: process.env, stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true });
    buffer = ''; bytes = 0;
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      bytes += Buffer.byteLength(chunk);
      if (!pending || bytes > MAX_OUTPUT) { stop('ast-worker-error'); return; }
      if (pending.reason) return; // A response after the deadline cannot pass.
      buffer += chunk;
      const end = buffer.indexOf('\n');
      if (end < 0) return;
      try {
        if (end !== buffer.length - 1) throw Error('unexpected response');
        const result = JSON.parse(buffer.slice(0, end));
        if (!validResult(result)) throw Error('invalid response');
        buffer = ''; bytes = 0;
        const { resolve, timer } = pending; pending = null; clearTimeout(timer); resolve(result);
      } catch (_) { stop('ast-worker-error'); }
    });
    child.on('error', () => stop('ast-worker-error'));
    child.stdin.on('error', () => stop('ast-worker-error'));
    child.on('close', () => {
      child = null;
      if (pending) {
        const { resolve, timer, reason } = pending; pending = null; clearTimeout(timer);
        resolve(failure(reason || 'ast-worker-error'));
      }
    });
  }
  function stop(reason) {
    if (pending) pending.reason = pending.reason || reason;
    if (child) child.kill('SIGKILL');
  }
  const results = [];
  let resultBytes = 0;
  try {
    for (const input of inputs) {
      if (!child) start();
      const result = await new Promise((resolve) => {
        pending = { resolve, timer: setTimeout(() => stop('ast-timeout'), TIMEOUT_MS) };
        child.stdin.write(JSON.stringify(input) + '\n');
      });
      resultBytes += Buffer.byteLength(JSON.stringify(result));
      if (resultBytes > MAX_OUTPUT - 16384) {
        while (results.length < inputs.length) results.push(failure('ast-resource-limit'));
        break;
      }
      results.push(result);
    }
  } finally {
    if (child) {
      const current = child;
      await new Promise((resolve) => { current.once('close', resolve); current.kill('SIGKILL'); });
    }
  }
  fs.writeSync(1, JSON.stringify(results));
}
main().catch(() => { process.exitCode = 1; });
