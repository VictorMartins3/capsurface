'use strict';

const fs = require('fs');
const { loadParser, astImports } = require('./ast-imports');

let parser;
function analyze(input) {
  const { code, file, sourceType, identity } = input;
  if (!parser) parser = loadParser();
  if (parser.identity !== identity) throw new Error('parser identity changed');
  return astImports(parser, code, file, sourceType);
}
if (process.argv.includes('--stream')) {
  const lines = require('readline').createInterface({ input: process.stdin });
  lines.on('line', (line) => {
    try { fs.writeSync(1, JSON.stringify(analyze(JSON.parse(line))) + '\n'); }
    catch (_) { process.exit(1); }
  });
} else {
  try { fs.writeSync(1, JSON.stringify(analyze(JSON.parse(fs.readFileSync(0, 'utf8'))))); }
  catch (_) { process.exitCode = 1; }
}
