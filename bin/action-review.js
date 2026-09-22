#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const cli = path.join(__dirname, 'capsurface.js');

function main() {
  const project = path.resolve(process.env.CAPSURFACE_PROJECT || '.');
  const baseline = process.env.CAPSURFACE_BASELINE || 'capsurface.lock.json';
  const lockfile = process.env.CAPSURFACE_LOCKFILE || 'package-lock.json';
  const baseRef = process.env.CAPSURFACE_BASE_REF || '';
  const failOnNew = process.env.CAPSURFACE_FAIL_ON_NEW || 'true';
  if (!['true', 'false'].includes(failOnNew)) throw new Error('fail-on-new must be true or false');
  if (baseRef && !/^(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/.test(baseRef)) throw new Error('base-ref must be a full commit SHA');
  for (const value of [baseline, lockfile]) {
    if (path.isAbsolute(value) || value.replace(/\\/g, '/').split('/').includes('..') || /[\r\n\0]/.test(value)) {
      throw new Error('baseline and lockfile must be paths within the project directory');
    }
  }
  const directory = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'capsurface-review-'));
  const manifests = path.join(directory, 'manifests');
  function command(executable, args, accepted = [0]) {
    const result = spawnSync(executable, args, { cwd: project, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
    if (result.error) throw result.error;
    if (!accepted.includes(result.status)) throw new Error(`${path.basename(executable)} failed (${result.status}): ${result.stderr || result.stdout}`);
    return result;
  }
  const run = (args, accepted) => command(process.execPath, [cli, ...args], accepted);
  const repository = command('git', ['rev-parse', '--show-toplevel']).stdout.trim();
  let target = path.resolve(project, baseline);
  if (baseRef) {
    const prefix = command('git', ['rev-parse', '--show-prefix']).stdout.trim();
    const content = command('git', ['show', `${baseRef}:${prefix}${baseline.replace(/\\/g, '/')}`]).stdout;
    target = path.join(directory, 'target-baseline.json');
    fs.writeFileSync(target, content);
  }
  // A scan with incomplete package analysis may still have a valid inventory.
  // review/check keep that failure visible; a broken inventory remains fatal.
  const scan = run(['scan-tree', 'node_modules', '--out', manifests], [0, 2]);
  process.stdout.write(scan.stdout);
  process.stderr.write(scan.stderr);
  const flags = failOnNew === 'true' ? ['--fail-on-new'] : [];
  const review = ['review', manifests, '--baseline', target, '--lockfile', lockfile, '--project-root', repository, ...flags, '--report-only'];
  const output = { directory, 'analysis-incomplete': String(scan.status !== 0) };
  for (const [format, extension] of [['markdown', 'md'], ['json', 'json'], ['sarif', 'sarif']]) {
    output[format] = path.join(directory, `review.${extension}`);
    run([...review, '--format', format, '--out', output[format]]);
  }
  const check = run(['check', manifests, '--baseline', baseline, ...flags, '--json'], [0, 1]);
  output['would-fail'] = String(check.status === 1);
  fs.writeFileSync(path.join(directory, 'proposed-check.json'), check.stdout);
  if (process.env.GITHUB_STEP_SUMMARY) {
    const markdown = fs.readFileSync(output.markdown, 'utf8');
    const summary = Buffer.byteLength(markdown) < 900000 ? markdown
      : markdown.slice(0, 200000) + '\n\nReport shortened for the job summary. Download the review artifact for the full findings.\n';
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,
      `Proposed baseline check: **${check.status === 1 ? 'FAIL' : 'PASS'}**.\n\n` + summary);
  }
  if (process.env.GITHUB_OUTPUT) {
    for (const [key, value] of Object.entries(output)) {
      if (/[\r\n]/.test(value)) throw new Error('invalid newline in output path');
      fs.appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${value}\n`);
    }
  }
  console.log(`Dependency review written to ${directory}`);
}

try { main(); } catch (error) { console.error(`capsurface action: ${error.message}`); process.exitCode = 2; }
