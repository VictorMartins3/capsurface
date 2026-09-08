'use strict';

/**
 * Capability categories for static capability-surface analysis.
 *
 * This is deliberately a *static, heuristic* classifier (regex over source
 * text), not a sound analysis. It cannot see through obfuscation, dynamic
 * `require(computedString)`, or code fetched at runtime. It is a triage
 * signal for CI/PR review, not a security boundary. Pair it with runtime
 * sandboxing (WASI/microVM/etc.) for actual enforcement.
 */

const CATEGORIES = [
  {
    key: 'filesystem',
    label: 'Filesystem access',
    severity: 2,
    patterns: [
      /\brequire\(\s*['"]fs(\/promises)?['"]\s*\)/,
      /\bfrom\s+['"]fs(\/promises)?['"]/,
      /\bfs\.(readFile|writeFile|appendFile|unlink|readdir|mkdir|rmdir|rm|stat|createReadStream|createWriteStream|readFileSync|writeFileSync|unlinkSync|readdirSync|existsSync)\b/,
    ],
  },
  {
    key: 'network',
    label: 'Network access',
    severity: 3,
    // `fetch` is deliberately NOT matched as a bare `fetch(`. That matched
    // any function or method named fetch, and "fetch" is a common name for
    // "populate a value" in caching and data layers: lru-cache's cache-fill
    // method is `fetch(k, opts)`, which made lru-cache and everything
    // bundling it (glob, via path-scurry) read as having network access.
    // These idioms cover real uses of the web API instead. A call through
    // an aliased reference (`const f = fetch; f(url)`) is not caught, which
    // is the same class of evasion documented in the README's limitations.
    patterns: [
      /\brequire\(\s*['"](node:)?(https?|net|dgram|tls|dns)['"]\s*\)/,
      /\bfrom\s+['"](node:)?(https?|net|dgram|tls|dns)['"]/,
      /\bawait\s+fetch\s*\(/,
      /\bfetch\s*\(\s*['"`]https?:\/\//,
      /\b(?:globalThis|window|self)\.fetch\s*\(/,
      /\bnew\s+XMLHttpRequest\b/,
      /\bnew\s+WebSocket\s*\(/,
      /\brequire\(\s*['"](axios|node-fetch|undici|got|superagent|request)['"]\s*\)/,
      /\bfrom\s+['"](axios|node-fetch|undici|got|superagent|request)['"]/,
      /\.(connect|createConnection)\s*\(/,
    ],
  },
  {
    key: 'exec',
    label: 'Process execution',
    severity: 4,
    // Note: intentionally keyed off importing the `child_process` module
    // rather than matching bare call sites like `exec(` / `spawn(`: those
    // names collide with unrelated APIs (e.g. RegExp.prototype.exec()),
    // which produced false positives in testing. Requiring the module is a
    // precise, low-noise proxy for "this file acquired exec capability".
    patterns: [
      /\brequire\(\s*['"]child_process['"]\s*\)/,
      /\bfrom\s+['"]child_process['"]/,
    ],
  },
  {
    key: 'env',
    label: 'Environment variable access',
    severity: 2,
    // Reading env vars is not a security event by itself. Upgrading 14
    // popular packages made four of them start reading one (no_proxy,
    // NO_COLOR, __MINIMATCH_TESTING_PLATFORM__), all routine configuration.
    // Credential-shaped reads are what matter, and the sensitiveTargets
    // category below covers those (NPM_TOKEN, GITHUB_TOKEN, AWS_*), as does
    // the credential check on newly-referenced names in lib/diff.js. So this
    // category is recorded and scored, but appearing does not fail a build
    // on its own.
    gatesOnAppear: false,
    patterns: [
      /\bprocess\.env\.[A-Za-z_][A-Za-z0-9_]*/,
      /\bprocess\.env\[\s*['"][^'"]+['"]\s*\]/,
    ],
  },
  {
    key: 'dynamicEval',
    label: 'Dynamic code execution',
    severity: 4,
    patterns: [
      /\beval\s*\(/,
      /\bnew\s+Function\s*\(/,
      /\bvm\.(runIn|Script)\b/,
    ],
  },
  {
    key: 'nativeFfi',
    label: 'Native / FFI code',
    severity: 3,
    patterns: [
      /\brequire\(\s*['"]ffi-napi['"]\s*\)/,
      /\bprocess\.binding\s*\(/,
      /\.node['"]\s*\)/,
    ],
  },
  {
    key: 'sensitiveTargets',
    label: 'Sensitive credential/file targeting',
    severity: 5,
    patterns: [
      /\.npmrc\b/,
      /\.ssh\//,
      /\bid_rsa\b/,
      /\.aws\/credentials\b/,
      /\.netrc\b/,
      /\bGITHUB_TOKEN\b/,
      /\bNPM_TOKEN\b/,
      /\bAWS_(ACCESS_KEY|SECRET_ACCESS_KEY)\b/,
      /\b_authToken\b/,
    ],
  },
];

// Matched separately: extracted evidence, not a pass/fail category on its own.
const URL_PATTERN = /https?:\/\/[a-zA-Z0-9\-._~%]+(?::[0-9]+)?[^\s'"`)]*/g;
const ENV_VAR_PATTERN = /process\.env\.([A-Za-z_][A-Za-z0-9_]*)|process\.env\[\s*['"]([^'"]+)['"]\s*\]/g;

// Heuristic obfuscation/minification signal: very long single lines are a
// common shape for packed/obfuscated payloads. Excluded for files that look
// like build artifacts (see looksLikeBuildArtifact in scanner.js). A
// legitimate minified dist bundle would otherwise trip this on nearly every
// popular package, training reviewers to ignore the signal.
const LONG_LINE_THRESHOLD = 500;

// Env var names worth failing a build over when a dependency starts
// reading one it did not read before. Testing a routine dependency upgrade
// across 14 popular packages produced new env var reads in four of them
// (no_proxy, NO_COLOR, FORCE_COLOR, DOTENV_CONFIG_QUIET,
// __MINIMATCH_TESTING_PLATFORM__), none of them security-relevant. Gating
// on every new env var name is therefore almost pure noise, while gating
// on credential-shaped names keeps the signal that matters.
const CREDENTIAL_ENV_PATTERN =
  /(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|API_?KEY|ACCESS_KEY|SESSION|COOKIE|_AUTH|AUTH_|^AUTH$|NPM_|AWS_|GITHUB_|^GH_|GITLAB_|GCP_|GOOGLE_|AZURE_|SSH_|DOCKER_|KUBE)/i;

// All lifecycle script keys we track and surface in the manifest.
const LIFECYCLE_SCRIPT_KEYS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];

// Subset of lifecycle scripts that actually execute for a normal consumer
// running `npm install <pkg>` against a registry tarball. Verified against
// npm's documented behavior: `prepare` (and `prepublish`) run only on a
// local `npm install` with no args (developing the package itself) or when
// installing the package from a git URL. They do NOT run when the package
// is installed as a registry dependency, which is the overwhelming majority
// of real installs. `preinstall`/`install`/`postinstall` run unconditionally
// for every consumer. This distinction matters: treating `prepare` the same
// as `postinstall` produced false CRITICAL "worm pattern" flags on real,
// popular, safe packages (glob, axios) during testing, purely because they
// ship a `prepare` build script (tshy/husky) alongside normal network code
// elsewhere in the package. It also tracks the actual attack surface: the
// Shai-Hulud campaign (Sept 2025) used postinstall; Shai-Hulud V2 (Nov 2025)
// switched to preinstall specifically so the payload runs even if the
// install subsequently fails. Neither variant used prepare.
const INSTALL_TRIGGERING_SCRIPT_KEYS = ['preinstall', 'install', 'postinstall'];

module.exports = {
  CATEGORIES,
  URL_PATTERN,
  ENV_VAR_PATTERN,
  CREDENTIAL_ENV_PATTERN,
  LONG_LINE_THRESHOLD,
  LIFECYCLE_SCRIPT_KEYS,
  INSTALL_TRIGGERING_SCRIPT_KEYS,
};
