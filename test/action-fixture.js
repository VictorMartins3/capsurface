'use strict';

// Hosted Action smoke test: only copies and scans source. Neither fixture runs.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const root = path.resolve(process.argv[2]);
const repo = path.join(__dirname, '..');
const cli = path.join(repo, 'bin', 'capsurface.js');
fs.mkdirSync(root, { recursive: true });
const target = path.join(root, 'node_modules', 'handy-color-utils');
const run = (...args) => execFileSync(process.execPath, [cli, ...args], { cwd: root, stdio: 'pipe' });
const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
function install(version) {
  fs.rmSync(target, { recursive: true, force: true });
  fs.cpSync(path.join(repo, 'examples', `malicious-pkg-v${version}`), target, { recursive: true });
  const pkg = JSON.parse(fs.readFileSync(path.join(target, 'package.json')));
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({ name: 'action-fixture', lockfileVersion: 3,
    packages: { '': { name: 'action-fixture', dependencies: { [pkg.name]: pkg.version } },
      [`node_modules/${pkg.name}`]: { name: pkg.name, version: pkg.version } } }, null, 2));
}
install(1);
run('scan-tree', 'node_modules', '--out', 'baseline-manifests');
run('baseline', 'baseline-manifests', '--out', 'capsurface.lock.json');
git('init', '--quiet');
git('add', 'capsurface.lock.json', 'package-lock.json');
git('-c', 'user.name=Integration Test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false',
  '-c', 'core.hooksPath=' + path.join(root, 'no-hooks'), 'commit', '--quiet', '-m', 'Record the reviewed dependency');
const sha = git('rev-parse', 'HEAD');
install(2);
if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `base-sha=${sha}\n`);
console.log(sha);
