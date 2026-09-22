'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {
  CATEGORIES,
  URL_PATTERN,
  ENDPOINT_TRAILING_JUNK,
  ENDPOINT_HOST,
  ENV_VAR_PATTERN,
  CREDENTIAL_ENV_PATTERN,
  LONG_LINE_THRESHOLD,
  GENERATED_LONG_LINE,
  MIN_LONG_LINES_FOR_OBFUSCATION,
  LIFECYCLE_SCRIPT_KEYS,
  INSTALL_TRIGGERING_SCRIPT_KEYS,
  DECLARATION_FILE_PATTERN,
  ERASED_SYNTAX,
  INSTALL_COMMAND_RULES,
  INERT_INSTALL_COMMAND,
  UNRESOLVED_REQUIRE,
  LOCAL_SPECIFIER,
  EXECUTABLE_SHEBANG_PATTERN,
} = require('./categories');

/**
 * A fingerprint of every rule that decides what lands in a manifest.
 *
 * A baseline records what the rules said when it was approved. Edit a rule
 * and the same package yields a different manifest, so the baseline quietly
 * starts meaning something else. `check` compares this and says so, because
 * "your rules changed" and "your dependencies changed" are different events
 * and a gate must not conflate them.
 */
function computeRulesVersion() {
  const shape = {
    // Normalization, coverage and gating changes also change what an
    // approval means, even when none of the pattern strings changed.
    engine: ['scanner.js', 'normalize.js', 'discovery.js', 'diff.js', 'comparison.js', 'filesystem-operations.js', 'content-integrity.js', 'approval-policy.js', 'source-context.js', 'install-context.js', 'ast-imports.js'].map((file) =>
      crypto.createHash('sha256').update(fs.readFileSync(path.join(__dirname, file), 'utf8').replace(/\r\n/g, '\n')).digest('hex')
    ),
    categories: CATEGORIES.map((c) => ({
      key: c.key,
      parent: c.parent || null,
      severity: c.severity,
      gatesOnAppear: c.gatesOnAppear !== false,
      patterns: c.patterns.map((p) => (p instanceof RegExp ? String(p) : [String(p.match), String(p.context)])),
    })),
    url: String(URL_PATTERN),
    endpointJunk: String(ENDPOINT_TRAILING_JUNK),
    endpointHost: String(ENDPOINT_HOST),
    env: String(ENV_VAR_PATTERN),
    credentialEnv: String(CREDENTIAL_ENV_PATTERN),
    longLineThreshold: LONG_LINE_THRESHOLD,
    minLongLines: MIN_LONG_LINES_FOR_OBFUSCATION,
    generatedLongLine: GENERATED_LONG_LINE.map(String),
    lifecycle: LIFECYCLE_SCRIPT_KEYS,
    installTriggering: INSTALL_TRIGGERING_SCRIPT_KEYS,
    declarationFile: String(DECLARATION_FILE_PATTERN),
    erasedSyntax: ERASED_SYNTAX.map((r) => [r.key, r.declarationFileOnly, String(r.pattern)]),
    installCommand: INSTALL_COMMAND_RULES.map((r) => [r.key, String(r.pattern)]),
    executableShebang: String(EXECUTABLE_SHEBANG_PATTERN),
    inertInstallCommand: String(INERT_INSTALL_COMMAND),
    unresolvedRequire: String(UNRESOLVED_REQUIRE),
    localSpecifier: String(LOCAL_SPECIFIER),
  };
  return crypto.createHash('sha256').update(JSON.stringify(shape)).digest('hex').slice(0, 12);
}

module.exports = { RULES_VERSION: computeRulesVersion() };
