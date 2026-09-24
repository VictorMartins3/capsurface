#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

function main() {
  const env = process.env;
  if (env.CI_PIPELINE_SOURCE !== 'merge_request_event' || env.CI_MERGE_REQUEST_EVENT_TYPE !== 'detached') {
    throw new Error('requires a detached merge request pipeline');
  }
  const numeric = (value) => typeof value === 'string' && /^[1-9][0-9]*$/.test(value);
  if (![env.CI_PROJECT_ID, env.CI_MERGE_REQUEST_IID, env.CI_PIPELINE_ID, env.CI_JOB_ID].every(numeric) ||
      env.CI_PROJECT_ID !== env.CI_MERGE_REQUEST_SOURCE_PROJECT_ID || env.CI_PROJECT_ID !== env.CI_MERGE_REQUEST_TARGET_PROJECT_ID) {
    throw new Error('requires a same-project merge request');
  }
  const sha = (value) => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value);
  if (!sha(env.CAPSURFACE_BASE_REF) || !sha(env.CI_COMMIT_SHA) || !env.CI_MERGE_REQUEST_TARGET_BRANCH_NAME) throw new Error('requires target SHA, source SHA and target branch');
  if (!['true', 'false'].includes(env.CAPSURFACE_REPORT_ONLY || 'false')) throw new Error('report-only must be true or false');
  const requestedProject = path.resolve(env.CAPSURFACE_PROJECT || env.CI_PROJECT_DIR || '.');
  const project = fs.realpathSync(requestedProject);
  const head = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: project, encoding: 'utf8' });
  if (head.status !== 0 || head.stdout.trim() !== env.CI_COMMIT_SHA) throw new Error('checkout does not match the merge request source SHA');
  // Use a dedicated empty directory so stale successful artifacts cannot survive.
  const relative = path.relative(requestedProject, path.resolve(requestedProject, env.CAPSURFACE_OUTPUT || '.capsurface/gitlab'));
  const output = path.resolve(project, relative);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('output must be a dedicated directory inside the project');
  fs.mkdirSync(output, { recursive: true });
  const realOutput = fs.realpathSync(output);
  if (path.relative(project, realOutput).startsWith('..') || fs.readdirSync(output).length) throw new Error('output must be empty and inside the project');
  const statusFile = path.join(output, 'status.json');
  fs.writeFileSync(statusFile, JSON.stringify({ complete: false }));
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'capsurface-gitlab-'));
  function copy(from, to) {
    fs.mkdirSync(to, { recursive: true });
    for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
      if (entry.isDirectory()) copy(path.join(from, entry.name), path.join(to, entry.name));
      else if (entry.isFile()) fs.copyFileSync(path.join(from, entry.name), path.join(to, entry.name));
      else throw new Error('unexpected review artifact type');
    }
  }
  function remove(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) remove(file); else fs.unlinkSync(file);
    }
    fs.rmdirSync(directory);
  }
  try {
    const outputs = path.join(temporary, 'outputs');
    const childEnv = { ...env, CAPSURFACE_PROJECT: project, RUNNER_TEMP: temporary,
      GITHUB_OUTPUT: outputs, GITHUB_STEP_SUMMARY: '' };
    delete childEnv.CAPSURFACE_GITLAB_TOKEN;
    const run = spawnSync(process.execPath, [path.join(__dirname, 'action-review.js')], {
      cwd: project, env: childEnv, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
    });
    process.stdout.write(run.stdout || '');
    process.stderr.write(run.stderr || '');
    if (run.error || run.status !== 0) throw new Error('review failed; no passing status was produced');
    const values = Object.fromEntries(fs.readFileSync(outputs, 'utf8').trim().split('\n').map((line) => {
      const i = line.indexOf('='); return [line.slice(0, i), line.slice(i + 1)];
    }));
    if (!['true', 'false'].includes(values['would-fail']) || !['true', 'false'].includes(values['analysis-incomplete'])) throw new Error('invalid review status');
    copy(values.directory, output);
    const status = { complete: true, gate: values['would-fail'] === 'true', incomplete: values['analysis-incomplete'] === 'true',
      projectId: env.CI_PROJECT_ID, iid: env.CI_MERGE_REQUEST_IID, pipelineId: env.CI_PIPELINE_ID, jobId: env.CI_JOB_ID,
      headSha: env.CI_COMMIT_SHA, targetSha: env.CAPSURFACE_BASE_REF, targetBranch: env.CI_MERGE_REQUEST_TARGET_BRANCH_NAME };
    fs.writeFileSync(statusFile, JSON.stringify(status, null, 2) + '\n');
    console.log(`GitLab review artifacts: ${output}`);
    process.exitCode = status.incomplete ? 2 : status.gate && env.CAPSURFACE_REPORT_ONLY !== 'true' ? 1 : 0;
  } finally { remove(temporary); }
}

try { main(); } catch (error) { console.error(`capsurface GitLab: ${error.message}`); process.exitCode = 2; }
