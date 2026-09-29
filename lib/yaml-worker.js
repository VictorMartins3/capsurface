'use strict';

// This process parses data only. It never loads code from the scanned project.
try {
  if (require('yaml/package.json').version !== '2.9.1') throw new Error('Install yaml@2.9.1 alongside capsurface for pnpm lockfiles');
  const yaml = require('yaml');
  const source = require('fs').readFileSync(0, 'utf8');
  const document = yaml.parseDocument(source, { uniqueKeys: true, stringKeys: true, strict: true });
  if (document.errors.length || document.warnings.length) throw new Error('Invalid or unsupported YAML');
  // Lockfiles do not need YAML aliases, custom tags or multiple documents.
  yaml.visit(document, { Alias() { throw new Error('YAML aliases are unsupported'); } });
  process.stdout.write(JSON.stringify({ lock: document.toJS({ maxAliasCount: 0 }) }));
} catch (error) {
  process.stdout.write(JSON.stringify({ error: error.code === 'MODULE_NOT_FOUND'
    ? 'Install yaml@2.9.1 alongside capsurface for pnpm lockfiles' : error.message }));
}
