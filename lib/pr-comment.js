'use strict';

const https = require('https');
const { renderMarkdown } = require('./review');

function apiClient(token, base = 'https://api.github.com') {
  const root = new URL(base);
  if (root.protocol !== 'https:' || root.username || root.password) throw new Error('Invalid GitHub API URL');
  return (method, route, body) => new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const req = https.request(new URL(root.pathname.replace(/\/$/, '') + route, root.origin), {
      method, headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json',
        'User-Agent': 'capsurface', 'X-GitHub-Api-Version': '2022-11-28',
        ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}) },
    }, (res) => {
      let value = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        value += chunk;
        if (value.length > 8 * 1024 * 1024) res.destroy(new Error('GitHub response too large'));
      });
      res.on('error', reject);
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) return reject(new Error(`GitHub HTTP ${res.statusCode}`));
        try { resolve(value ? JSON.parse(value) : null); } catch (_) { reject(new Error('Invalid GitHub response')); }
      });
    });
    req.setTimeout(15000, () => req.destroy(new Error('GitHub request timed out')));
    req.on('error', reject);
    req.end(data);
  });
}

async function publishComment({ event, eventName, repository, key = 'default', report, gate, incomplete, request }) {
  const pr = event.pull_request;
  // Never add a privileged pull_request_target path to get around fork permissions.
  // A deleted fork leaves head.repo null; that is a skip, not a crash.
  if (eventName !== 'pull_request' || !pr || !pr.head || !pr.base || !pr.head.repo || !pr.base.repo ||
      pr.head.repo.full_name !== repository || pr.base.repo.full_name !== repository) return 'skipped-event';
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository) || !Number.isSafeInteger(event.number) || event.number < 1 ||
      !/^[\w.-]{1,80}$/.test(key)) throw new Error('Invalid comment context');
  const prefix = `/repos/${repository}`;
  const marker = `<!-- capsurface-review:${key} -->`;
  // Review IDs identify approval inputs, not a change in the displayed findings.
  const markdown = renderMarkdown(report).replace(/^Review ID: .*\n/gm, '');
  const status = incomplete ? 'INCOMPLETE' : gate ? 'FAIL' : 'PASS';
  const content = `## Capsurface dependency review\n\nProposed baseline check: **${status}**.\n\n${markdown}`;
  const body = `${marker}\n${content.length > 50000 ? content.slice(0, 50000) + '\n\nReport shortened. Full findings are available in the workflow job summary and report outputs.' : content}`;
  const comments = [];
  for (let page = 1; ; page++) {
    const batch = await request('GET', `${prefix}/issues/${event.number}/comments?per_page=100&page=${page}`);
    if (!Array.isArray(batch)) throw new Error('Invalid GitHub comments response');
    comments.push(...batch);
    if (batch.length < 100) break;
    if (page === 10) throw new Error('Comment pagination limit reached');
  }
  const existing = comments.find((comment) => comment.user && comment.user.type === 'Bot' &&
    ['github-actions[bot]', 'github-actions'].includes(comment.user.login) &&
    typeof comment.body === 'string' && comment.body.startsWith(marker + '\n'));
  if (existing && existing.body === body) return 'unchanged';
  if (!existing && !gate && !incomplete && report.entries.length === 0) return 'clean';
  // A completed old run must not overwrite a newer commit's report.
  const live = await request('GET', `${prefix}/pulls/${event.number}`);
  if (live.state !== 'open' || live.head.sha !== pr.head.sha || live.base.sha !== pr.base.sha) return 'stale';
  if (existing) {
    if (!Number.isSafeInteger(existing.id) || existing.id < 1) throw new Error('Invalid comment ID');
    await request('PATCH', `${prefix}/issues/comments/${existing.id}`, { body });
    return 'updated';
  }
  await request('POST', `${prefix}/issues/${event.number}/comments`, { body });
  return 'created';
}

module.exports = { apiClient, publishComment };
