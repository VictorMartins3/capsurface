#!/usr/bin/env node
'use strict';

const fs = require('fs');
const { apiClient, publishComment } = require('../lib/pr-comment');

async function main() {
  const token = process.env.CAPSURFACE_COMMENT_TOKEN;
  if (!token) { console.log('PR comment skipped: no token. Read the job summary.'); return; }
  const result = await publishComment({
    event: JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8')),
    eventName: process.env.GITHUB_EVENT_NAME,
    repository: process.env.GITHUB_REPOSITORY,
    key: process.env.CAPSURFACE_COMMENT_KEY || 'default',
    report: JSON.parse(fs.readFileSync(process.env.CAPSURFACE_COMMENT_REPORT, 'utf8')),
    gate: process.env.CAPSURFACE_COMMENT_GATE === 'true',
    incomplete: process.env.CAPSURFACE_COMMENT_INCOMPLETE === 'true',
    request: apiClient(token, process.env.GITHUB_API_URL),
  });
  console.log(`PR comment: ${result}. Full results remain in the job summary.`);
}

main().catch(() => {
  // API failures must not replace the independent capability gate or leak tokens.
  console.log('::warning::Could not update the capsurface PR comment. Check pull-requests write permission; full results remain in the job summary.');
});
