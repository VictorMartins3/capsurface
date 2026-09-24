'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { publishComment } = require('../lib/pr-comment');
const { mkTmpDir } = require('./helpers');

function fixture() {
  const context = { eventName: 'pull_request', repository: 'owner/repo',
    event: { number: 4, pull_request: { head: { sha: 'head', repo: { full_name: 'owner/repo' } },
      base: { sha: 'base', repo: { full_name: 'owner/repo' } } } },
    report: { manifestsScanned: 1, wouldFail: true, entries: [] }, gate: true, incomplete: false };
  const comments = [], writes = [];
  let stale = false;
  context.request = async (method, route, data) => {
    if (method === 'GET' && route.includes('/comments?')) return comments;
    if (method === 'GET') return { state: 'open', head: { sha: stale ? 'newer' : 'head' }, base: { sha: 'base' } };
    writes.push({ method, route, data });
    if (method === 'POST') comments.push({ id: 123, user: { type: 'Bot', login: 'github-actions[bot]' }, body: data.body });
    else comments.find((c) => c.id === 123).body = data.body;
  };
  return { context, comments, writes, stale: () => { stale = true; } };
}

test('creates once, skips identical runs and updates the same comment when the gate clears', async () => {
  const f = fixture();
  assert.equal(await publishComment(f.context), 'created');
  for (let i = 0; i < 5; i++) assert.equal(await publishComment(f.context), 'unchanged');
  assert.equal(f.writes.length, 1);
  f.context.gate = false;
  f.context.report.wouldFail = false;
  assert.equal(await publishComment(f.context), 'updated');
  assert.equal(f.writes[1].method, 'PATCH');
  assert.match(f.writes[1].data.body, /Proposed baseline check: \*\*PASS\*\*/);
  assert.equal(await publishComment(f.context), 'unchanged');
  const clean = fixture();
  clean.context.gate = false;
  assert.equal(await publishComment(clean.context), 'clean');
  assert.equal(clean.writes.length, 0);
});

test('does not trust copied markers, skips forks and privileged events, and rejects stale runs', async () => {
  const f = fixture();
  f.comments.push({ id: 1, user: { type: 'User', login: 'someone' }, body: '<!-- capsurface-review:default -->\nold' });
  assert.equal(await publishComment(f.context), 'created');
  assert.equal(f.writes[0].method, 'POST');
  f.context.incomplete = true;
  f.stale();
  assert.equal(await publishComment(f.context), 'stale');
  assert.equal(f.writes.length, 1);
  f.context.request = () => { throw new Error('No API call allowed'); };
  f.context.event.pull_request.head.repo.full_name = 'fork/repo';
  assert.equal(await publishComment(f.context), 'skipped-event');
  f.context.event.pull_request.head.repo.full_name = 'owner/repo';
  f.context.eventName = 'pull_request_target';
  assert.equal(await publishComment(f.context), 'skipped-event');
});

test('finds the existing comment beyond the first page and isolates comment keys', async () => {
  const f = fixture();
  await publishComment(f.context);
  const saved = f.comments[0];
  const writes = [];
  f.context.gate = false;
  f.context.request = async (method, route, data) => {
    if (route.endsWith('&page=1')) return Array.from({ length: 100 }, () => ({ body: 'unrelated' }));
    if (route.endsWith('&page=2')) return [saved];
    if (method === 'GET') return { state: 'open', head: { sha: 'head' }, base: { sha: 'base' } };
    writes.push({ method, data });
  };
  assert.equal(await publishComment(f.context), 'updated');
  assert.equal(writes[0].method, 'PATCH');
  f.context.key = 'another-project';
  f.context.gate = true;
  assert.equal(await publishComment(f.context), 'created');
  assert.equal(writes[1].method, 'POST');
});

test('a rejected update stops without falling back to a duplicate comment', async () => {
  const f = fixture();
  await publishComment(f.context);
  const oldBody = f.comments[0].body;
  f.context.gate = false;
  const request = f.context.request;
  const attempts = [];
  f.context.request = async (method, route, data) => {
    attempts.push(method);
    if (method === 'PATCH') throw new Error('GitHub HTTP 403');
    return request(method, route, data);
  };
  await assert.rejects(publishComment(f.context), /403/);
  assert.deepEqual(attempts, ['GET', 'GET', 'PATCH']);
  assert.equal(f.comments.length, 1);
  assert.equal(f.comments[0].body, oldBody);
  assert.equal(f.context.report.wouldFail, true);
});

test('approval ID churn is quiet while evidence changes update the comment', async () => {
  const f = fixture();
  f.context.report.entries = [{ id: 'old-id', name: 'pkg', baselineVersion: '1', currentVersion: '2',
    installPath: 'pkg', match: { kind: 'single-baseline' }, requiresApproval: true,
    approvable: true, changes: [], newRiskFlags: [],
    evidence: [{ file: 'index.js', line: 1, category: 'network', snippet: 'fetch(url)' }] }];
  assert.equal(await publishComment(f.context), 'created');
  f.context.report.entries[0].id = 'new-id';
  assert.equal(await publishComment(f.context), 'unchanged');
  f.context.report.entries[0].evidence[0].snippet = 'fetch(otherUrl)';
  assert.equal(await publishComment(f.context), 'updated');
});

test('Action wrapper preserves the gate and warns without leaking credentials after HTTP 403', () => {
  const fs = require('fs');
  const path = require('path');
  const { spawnSync } = require('child_process');
  const root = mkTmpDir('comment-permission');
  const eventFile = path.join(root, 'event.json');
  const reportFile = path.join(root, 'report.json');
  const callsFile = path.join(root, 'calls.json');
  const preload = path.join(root, 'mock-https.cjs');
  const { context } = fixture();
  fs.writeFileSync(eventFile, JSON.stringify(context.event));
  const originalReport = JSON.stringify(context.report);
  fs.writeFileSync(reportFile, originalReport);
  // Exercise the real HTTP client and wrapper in a child process without
  // contacting GitHub. Record every attempt before returning a denied response.
  fs.writeFileSync(preload, `
    const { EventEmitter } = require('events');
    const fs = require('fs');
    require('https').request = (url, options, callback) => {
      fs.appendFileSync(process.env.TEST_COMMENT_CALLS, JSON.stringify({ method: options.method, path: url.pathname }) + '\\n');
      const req = new EventEmitter();
      req.setTimeout = () => req;
      req.end = () => process.nextTick(() => {
        const res = new EventEmitter();
        res.statusCode = 403;
        res.setEncoding = () => {};
        callback(res);
        res.emit('data', JSON.stringify({ message: 'denied ' + options.headers.Authorization }));
        res.emit('end');
      });
      return req;
    };
  `);
  const result = spawnSync(process.execPath, ['--require', preload, path.join(__dirname, '../bin/action-comment.js')], {
    encoding: 'utf8', env: { ...process.env, NODE_OPTIONS: '',
      CAPSURFACE_COMMENT_TOKEN: 'secret-not-for-logs',
      GITHUB_EVENT_PATH: eventFile, GITHUB_EVENT_NAME: 'pull_request', GITHUB_REPOSITORY: 'owner/repo',
      GITHUB_API_URL: 'https://api.github.com', CAPSURFACE_COMMENT_KEY: 'default',
      CAPSURFACE_COMMENT_REPORT: reportFile, CAPSURFACE_COMMENT_GATE: 'true',
      CAPSURFACE_COMMENT_INCOMPLETE: 'false', TEST_COMMENT_CALLS: callsFile },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /::warning::.*job summary/);
  assert.ok(!(result.stdout + result.stderr).includes('secret-not-for-logs'));
  assert.equal(fs.readFileSync(reportFile, 'utf8'), originalReport);
  const attempts = fs.readFileSync(callsFile, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
  assert.deepEqual(attempts, [{ method: 'GET', path: '/repos/owner/repo/issues/4/comments' }]);
});

test('skips a pull request whose fork repository was deleted', async () => {
  const f = fixture();
  f.context.event.pull_request.head.repo = null;
  assert.equal(await publishComment(f.context), 'skipped-event');
  assert.equal(f.writes.length, 0);
});
