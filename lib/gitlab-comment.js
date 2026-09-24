'use strict';

const https = require('https');
const crypto = require('crypto');
const { renderMarkdown } = require('./review');

function gitlabClient(token, apiUrl) {
  const root = new URL(apiUrl);
  if (root.protocol !== 'https:' || root.username || root.password || root.search || root.hash) throw new Error('Invalid GitLab API URL');
  return (method, route, body) => new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const req = https.request(new URL(root.pathname.replace(/\/$/, '') + route, root.origin), {
      method, headers: { 'PRIVATE-TOKEN': token, Accept: 'application/json', 'User-Agent': 'capsurface',
        ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}) },
    }, (res) => {
      let value = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { value += chunk; if (value.length > 8 * 1024 * 1024) res.destroy(new Error('GitLab response too large')); });
      res.on('error', reject);
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) return reject(new Error(`GitLab HTTP ${res.statusCode}`));
        try { resolve(value ? JSON.parse(value) : null); } catch (_) { reject(new Error('Invalid GitLab response')); }
      });
    });
    req.setTimeout(15000, () => req.destroy(new Error('GitLab request timed out')));
    req.on('error', reject);
    req.end(data);
  });
}

async function publishGitlabComment({ status, report, key = 'default', request }) {
  if (!status || status.complete !== true) return 'incomplete-artifacts';
  if (![status.projectId, status.iid, status.pipelineId, status.jobId].every((v) => typeof v === 'string' && /^[1-9][0-9]*$/.test(v)) ||
      ![status.headSha, status.targetSha].every((v) => typeof v === 'string' && /^[a-f0-9]{40}$/.test(v)) ||
      typeof status.targetBranch !== 'string' || !status.targetBranch || typeof status.gate !== 'boolean' ||
      typeof status.incomplete !== 'boolean' || !/^[\w.-]{1,80}$/.test(key)) throw new Error('Invalid GitLab review context');
  const prefix = `/projects/${status.projectId}`;
  const route = `${prefix}/merge_requests/${status.iid}`;
  async function current() {
    const mr = await request('GET', route);
    if (mr.state !== 'opened' || String(mr.source_project_id) !== status.projectId || String(mr.target_project_id) !== status.projectId ||
        mr.sha !== status.headSha || mr.target_branch !== status.targetBranch) return false;
    const branch = await request('GET', `${prefix}/repository/branches/${encodeURIComponent(status.targetBranch)}`);
    return branch.commit.id === status.targetSha;
  }
  if (!await current()) return 'stale';
  const user = await request('GET', '/user');
  if (!Number.isSafeInteger(user.id) || user.id < 1) throw new Error('Invalid GitLab identity');
  const marker = `<!-- capsurface-review:${key} -->`;
  const markdown = renderMarkdown(report).replace(/^Review ID: .*\n/gm, '');
  const content = `## Capsurface dependency review\n\nProposed baseline check: **${status.incomplete ? 'INCOMPLETE' : status.gate ? 'FAIL' : 'PASS'}**.\n\n${markdown}`;
  const hash = crypto.createHash('sha256').update(content).digest('hex');
  const body = `${marker}\n<!-- capsurface-result:${hash} -->\n${content.length > 50000 ? content.slice(0, 50000) + '\n\nReport shortened. Full results are in the review job artifacts.' : content}`;
  let existing;
  for (let page = 1; ; page++) {
    const notes = await request('GET', `${route}/notes?per_page=100&page=${page}&sort=asc&order_by=created_at`);
    if (!Array.isArray(notes)) throw new Error('Invalid GitLab notes');
    existing = existing || notes.find((note) => !note.system && note.author && note.author.id === user.id && typeof note.body === 'string' && note.body.startsWith(marker + '\n'));
    if (notes.length < 100) break;
    if (page === 10) throw new Error('GitLab note pagination limit reached');
  }
  if (existing && existing.body === body) return 'unchanged';
  if (!existing && !status.gate && !status.incomplete && report.entries.length === 0) return 'clean';
  if (!await current()) return 'stale';
  if (existing) {
    if (!Number.isSafeInteger(existing.id) || existing.id < 1) throw new Error('Invalid GitLab note ID');
    await request('PUT', `${route}/notes/${existing.id}`, { body });
    return 'updated';
  }
  await request('POST', `${route}/notes`, { body });
  return 'created';
}

module.exports = { gitlabClient, publishGitlabComment };
