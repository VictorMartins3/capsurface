'use strict';

const crypto = require('crypto');
const {
  CATEGORIES,
  URL_PATTERN,
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
  EXECUTABLE_SHEBANG_PATTERN,
} = require('./categories');

/**
 * A fingerprint of every rule that decides what lands in a manifest.
 *
 * A baseline records what the rules said at the time it was approved. Change
 * a rule and the same package produces a different manifest, so the baseline
 * silently starts meaning something else: capabilities can appear or vanish
 * with no change to any dependency. That happened while tuning this tool
 * against real projects, and nothing anywhere reported it.
 *
 * `check` compares this against the baseline's value and says so when they
 * differ, because "your rules changed, re-baseline" and "your dependencies
 * changed" are different events and a security gate must not conflate them.
 */
function computeRulesVersion() {
  const shape = {
    categories: CATEGORIES.map((c) => ({
      key: c.key,
      severity: c.severity,
      gatesOnAppear: c.gatesOnAppear !== false,
      patterns: c.patterns.map((p) => (p instanceof RegExp ? String(p) : [String(p.match), String(p.context)])),
    })),
    url: String(URL_PATTERN),
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
  };
  return crypto.createHash('sha256').update(JSON.stringify(shape)).digest('hex').slice(0, 12);
}

module.exports = { RULES_VERSION: computeRulesVersion(), computeRulesVersion };
