'use strict';

const fs = require('fs');
const path = require('path');
let cached;

function typedParser(acorn) {
  if (cached !== undefined) return cached;
  let entry;
  try { entry = require.resolve('acorn-typescript'); } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') return (cached = null);
    throw error;
  }
  // The pinned package exposes lib/index.js, but not its package.json.
  const metadata = JSON.parse(fs.readFileSync(path.join(path.dirname(entry), '..', 'package.json'), 'utf8'));
  if (metadata.version !== '1.4.13') throw new Error('TypeScript/JSX analysis requires acorn-typescript@1.4.13');
  const { tsPlugin } = require(entry);
  const regular = acorn.Parser.extend(tsPlugin({ allowSatisfies: true }));
  const ambient = acorn.Parser.extend(tsPlugin({ dts: true, allowSatisfies: true }));
  cached = { version: metadata.version,
    parse(code, options, declarations) { return (declarations ? ambient : regular).parse(code, options); } };
  return cached;
}

module.exports = { typedParser };
