'use strict';

const fs = require('fs');
const { loadParser, astImports } = require('./ast-imports');

try {
  const { code, file, sourceType, identity } = JSON.parse(fs.readFileSync(0, 'utf8'));
  const parser = loadParser();
  if (parser.identity !== identity) throw new Error('parser identity changed');
  const result = astImports(parser, code, file, sourceType);
  fs.writeSync(1, JSON.stringify(result));
} catch (_) {
  process.exitCode = 1;
}
