'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { publishGitlabComment, gitlabClient } = require('../lib/gitlab-comment');
function fixture() {
  const notes = [], writes = [];
  const status = { complete: true, projectId: '1', iid: '2', pipelineId: '3', jobId: '4', headSha: 'a'.repeat(40), targetSha: 'b'.repeat(40), targetBranch: 'main', gate: true, incomplete: false };
  const mr = { state: 'opened', source_project_id: 1, target_project_id: 1, sha: status.headSha, target_branch: 'main' };
  const branch = { commit: { id: status.targetSha } };
  const options = { status, report: { manifestsScanned: 1, wouldFail: true, entries: [] }, request: async (method, route, data) => {
    if (method === 'GET') {
      if (route === '/user') return { id: 8 };
      if (route.includes('/notes?')) return notes;
      if (route.includes('/repository/branches/')) return branch;
      return mr;
    }
    writes.push({ method, route, data });
    if (method === 'POST') notes.push({ id: 7, author: { id: 8 }, body: data.body });
    else notes.find(n => n.id === 7).body = data.body;
  } };
  return { options, notes, writes, mr, branch };
}
test('GitLab creates one owned note, skips identical content and updates when the gate clears', async () => {
  const f = fixture();
  f.notes.push({ id: 99, author: { id: 9 }, body: '<!-- capsurface-review:default -->\ncopied' });
  assert.equal(await publishGitlabComment(f.options), 'created');
  assert.equal(await publishGitlabComment(f.options), 'unchanged');
  f.options.status.gate = false;
  assert.equal(await publishGitlabComment(f.options), 'updated');
  assert.deepEqual(f.writes.map(w => w.method), ['POST', 'PUT']);
  assert.match(f.writes[1].data.body, /\*\*PASS\*\*/);
  const clean = fixture(); clean.options.status.gate = false;
  assert.equal(await publishGitlabComment(clean.options), 'clean');
  assert.equal(clean.writes.length, 0);
});
test('GitLab rejects stale or fork context and never replaces a denied update with a new note', async () => {
  for (const change of [f => { f.mr.sha = 'c'.repeat(40); }, f => { f.branch.commit.id = 'c'.repeat(40); }, f => { f.mr.source_project_id = 9; }, f => { f.mr.state = 'closed'; }]) {
    const f = fixture(); change(f);
    assert.equal(await publishGitlabComment(f.options), 'stale');
    assert.equal(f.writes.length, 0);
  }
  const f = fixture(); await publishGitlabComment(f.options);
  f.options.status.gate = false;
  const request = f.options.request, attempts = [];
  f.options.request = async (method, route, body) => { attempts.push(method); if (method === 'PUT') throw new Error('403'); return request(method, route, body); };
  await assert.rejects(publishGitlabComment(f.options), /403/);
  assert.equal(attempts.filter(m => m === 'POST').length, 0);
  assert.equal(f.notes.length, 1);
});
test('GitLab pagination finds an existing note and limits incomplete inventories without posting', async () => {
  const f = fixture(); await publishGitlabComment(f.options);
  const saved = f.notes[0], request = f.options.request;
  f.options.status.incomplete = true;
  f.options.request = async (method, route, body) => route.includes('/notes?')
    ? route.includes('page=1&') ? Array.from({ length: 100 }, () => ({ body: 'other' })) : [saved]
    : request(method, route, body);
  assert.equal(await publishGitlabComment(f.options), 'updated');
  assert.match(f.writes[1].data.body, /INCOMPLETE/);
  f.options.request = async (method, route, body) => route.includes('/notes?')
    ? Array.from({ length: 100 }, () => ({ body: 'other' })) : request(method, route, body);
  await assert.rejects(publishGitlabComment(f.options), /pagination limit/);
  assert.equal(f.writes.length, 2);
  // A false artifact-complete flag must not even contact the API.
  f.options.status.complete = false;
  assert.equal(await publishGitlabComment(f.options), 'incomplete-artifacts');
  assert.throws(() => gitlabClient('secret', 'http://gitlab.example/api/v4'), /URL/);
});

test('GitLab after_script preserves gate artifacts and does not leak credentials on HTTP errors', () => {
  const fs = require('fs'), path = require('path');
  const { spawnSync } = require('child_process');
  const dir = require('./helpers').mkTmpDir('gitlab-http');
  const f = fixture();
  const statusFile = path.join(dir, 'status.json');
  const statusText = JSON.stringify(f.options.status);
  fs.writeFileSync(statusFile, statusText);
  fs.writeFileSync(path.join(dir, 'review.json'), JSON.stringify(f.options.report));
  const preload = path.join(dir, 'mock.cjs');
  fs.writeFileSync(preload, `
    const { EventEmitter } = require('events');
    require('https').request = (url, options, callback) => {
      require('fs').writeFileSync(process.env.TEST_CALL, JSON.stringify({method: options.method, path: url.pathname}));
      const req = new EventEmitter(); req.setTimeout = () => req;
      req.end = () => process.nextTick(() => {
        const res = new EventEmitter(); res.statusCode = 403; res.setEncoding = () => {};
        callback(res); res.emit('data', options.headers['PRIVATE-TOKEN']); res.emit('end');
      }); return req;
    };
  `);
  const call = path.join(dir, 'call.json');
  const args = ['--require', preload, path.join(__dirname, '../bin/gitlab-comment.js')];
  const options = {
    encoding: 'utf8', env: { ...process.env, NODE_OPTIONS: '', CAPSURFACE_OUTPUT: dir,
      CAPSURFACE_COMMENT_MR: 'true', CAPSURFACE_GITLAB_TOKEN: 'secret-never-print',
      CI_PIPELINE_SOURCE: 'merge_request_event', CI_MERGE_REQUEST_EVENT_TYPE: 'detached',
      CI_PROJECT_ID: '1', CI_MERGE_REQUEST_SOURCE_PROJECT_ID: '1', CI_MERGE_REQUEST_TARGET_PROJECT_ID: '1',
      CI_PIPELINE_ID: '3', CI_JOB_ID: '4', CI_MERGE_REQUEST_IID: '2', CI_COMMIT_SHA: f.options.status.headSha,
      CI_API_V4_URL: 'https://gitlab.example/api/v4', TEST_CALL: call },
  };
  const result = spawnSync(process.execPath, args, options);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /could not be updated/);
  assert.ok(!(result.stdout + result.stderr).includes('secret-never-print'));
  assert.equal(fs.readFileSync(statusFile, 'utf8'), statusText);
  assert.deepEqual(JSON.parse(fs.readFileSync(call)), { method: 'GET', path: '/api/v4/projects/1/merge_requests/2' });
  fs.unlinkSync(call);
  options.env.CI_JOB_ID = '5';
  assert.equal(spawnSync(process.execPath, args, options).status, 0);
  assert.equal(fs.existsSync(call), false, 'a retried job cannot publish old artifacts');
});
