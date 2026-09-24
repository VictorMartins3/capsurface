#!/usr/bin/env node
'use strict';

const path = require('path');
const { readBounded } = require('../lib/tarball');
const { gitlabClient, publishGitlabComment } = require('../lib/gitlab-comment');
async function main() {
  const env = process.env;
  if (env.CAPSURFACE_COMMENT_MR !== 'true' || !env.CAPSURFACE_GITLAB_TOKEN) { console.log('GitLab comment skipped. Reports remain in job artifacts.'); return; }
  if (env.CI_PIPELINE_SOURCE !== 'merge_request_event' || env.CI_MERGE_REQUEST_EVENT_TYPE !== 'detached' ||
      !env.CI_PROJECT_ID || env.CI_PROJECT_ID !== env.CI_MERGE_REQUEST_SOURCE_PROJECT_ID || env.CI_PROJECT_ID !== env.CI_MERGE_REQUEST_TARGET_PROJECT_ID) return;
  const output = path.resolve(env.CAPSURFACE_PROJECT || env.CI_PROJECT_DIR || '.', env.CAPSURFACE_OUTPUT || '.capsurface/gitlab');
  const status = JSON.parse(readBounded(path.join(output, 'status.json'), 1024 * 1024));
  if (status.projectId !== env.CI_PROJECT_ID || status.iid !== env.CI_MERGE_REQUEST_IID || status.pipelineId !== env.CI_PIPELINE_ID || status.jobId !== env.CI_JOB_ID || status.headSha !== env.CI_COMMIT_SHA) throw new Error('Artifacts do not match this pipeline');
  const report = JSON.parse(readBounded(path.join(output, 'review.json'), 64 * 1024 * 1024));
  console.log('GitLab comment: ' + await publishGitlabComment({ status, report, key: env.CAPSURFACE_COMMENT_KEY || 'default', request: gitlabClient(env.CAPSURFACE_GITLAB_TOKEN, env.CI_API_V4_URL) }));
}
main().catch(() => console.log('GitLab comment could not be updated. Check token permissions; review artifacts and gate remain unchanged.'));
