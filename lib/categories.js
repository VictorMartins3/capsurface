'use strict';

// Capability categories for static capability-surface analysis.
//
// This is a heuristic classifier over source text, not a sound analysis. It
// cannot see through obfuscation, `require(computedString)`, or code fetched
// at runtime. Treat it as triage for review, not as a security boundary.

// Doing something with a path, as opposed to naming one. Matched in a window
// around the path, not across the whole line; see CONTEXT_WINDOW.
const PATH_ACCESS =
  /\b(?:readFile|writeFile|appendFile|createReadStream|createWriteStream|open|unlink|stat|access|realpath|copyFile|rename|chmod|exists)[A-Za-z]*\s*\(|\bfs\w*\.\w+\s*\(|\bpath\.(?:join|resolve|normalize)\s*\(|\b(?:homedir|userInfo|tmpdir)\s*\(|\bprocess\.env\.(?:HOME|USERPROFILE)\b/;

const CATEGORIES = [
  {
    key: 'filesystem',
    label: 'Filesystem access',
    severity: 2,
    patterns: [
      /\b(?:require|import|_load)\s*(?:\?\.\s*)?\(\s*['"`](node:)?fs(\/promises)?['"`]\s*\)/,
      /\bfrom\s+['"](node:)?fs(\/promises)?['"]/,
      /\bfs\.(readFile|writeFile|appendFile|unlink|readdir|mkdir|rmdir|rm|stat|createReadStream|createWriteStream|readFileSync|writeFileSync|unlinkSync|readdirSync|existsSync)\b/,
    ],
  },
  // Operation detail is recorded separately without double-counting the
  // filesystem risk score. Detection lives in filesystem-operations.js.
  { key: 'filesystemRead', label: 'Filesystem read', parent: 'filesystem', severity: 0, patterns: [] },
  { key: 'filesystemWrite', label: 'Filesystem write', parent: 'filesystem', severity: 0, patterns: [] },
  { key: 'filesystemRemove', label: 'Filesystem removal', parent: 'filesystem', severity: 0, patterns: [] },
  {
    key: 'network',
    label: 'Network access',
    severity: 3,
    // Not a bare `fetch(`: lru-cache's cache-fill method is `fetch(k, opts)`,
    // which made everything bundling it read as networked. `.connect(` was
    // dropped for the same reason, since rxjs and inquirer both have one. An
    // aliased call (`const f = fetch; f(url)`) is a documented blind spot.
    patterns: [
      /\b(?:require|import|_load)\s*(?:\?\.\s*)?\(\s*['"`](node:)?(https?|http2|net|dgram|tls|dns)['"`]\s*\)/,
      /\bfrom\s+['"](node:)?(https?|http2|net|dgram|tls|dns)['"]/,
      /\bawait\s+fetch\s*\(/,
      /\bfetch\s*\(\s*['"`]https?:\/\//,
      /\b(?:globalThis|window|self)\.fetch\s*\(/,
      /\bnew\s+XMLHttpRequest\b/,
      /\bnew\s+WebSocket\s*\(/,
      /\b(?:require|import|_load)\s*(?:\?\.\s*)?\(\s*['"`](axios|node-fetch|undici|got|superagent|request)['"`]\s*\)/,
      /\bfrom\s+['"](axios|node-fetch|undici|got|superagent|request)['"]/,
    ],
  },
  {
    key: 'exec',
    label: 'Process execution',
    severity: 4,
    // Keyed on the import, not on `exec(` or `spawn(`, which collide with
    // RegExp.prototype.exec and with plenty of unrelated APIs.
    patterns: [
      /\b(?:require|import|_load)\s*(?:\?\.\s*)?\(\s*['"`](node:)?child_process['"`]\s*\)/,
      /\bfrom\s+['"](node:)?child_process['"]/,
    ],
  },
  {
    key: 'env',
    label: 'Environment variable access',
    severity: 2,
    // Reading an env var is not a security event by itself; upgrades add
    // NO_COLOR and no_proxy all the time. Credential-shaped reads are covered
    // by sensitiveTargets, so this is recorded and scored but does not gate.
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
    // `eval` must be eval: `$` is not a word character, so a bare \beval\b
    // also matched puppeteer's `$eval` and `redis.eval()` running Lua.
    // `new Function("return this")` is the globalThis polyfill every bundler
    // emits; its argument is a constant, so nothing chosen is executed.
    patterns: [
      /(?<![.$\w])eval\s*\(/,
      /\b(?:globalThis|window|self|global)\s*(\.|\[\s*['"`])eval(['"`]\s*\])?\s*\(/,
      /\(\s*0\s*,\s*eval\s*\)\s*\(/,
      /\bnew\s+Function\s*\((?!\s*(['"`])return (this|globalThis)\1\s*\))/,
      /\bvm\.(runIn|Script)\b/,
      /\b(?:require|import|_load)\s*(?:\?\.\s*)?\(\s*['"`](node:)?vm['"`]\s*\)/,
      /\bfrom\s+['"](node:)?vm['"]/,
    ],
  },
  {
    key: 'nativeFfi',
    label: 'Native / FFI code',
    severity: 3,
    // Keyed on loading native code. A bare ".node" suffix matched
    // comparisons, `if (!source.endsWith('.node'))`, not loads.
    patterns: [
      /\b(?:require|import|_load)\s*(?:\?\.\s*)?\(\s*['"`](ffi-napi|bindings|node-gyp-build|node-gyp-build-optional-packages)['"`]\s*\)/,
      /\bprocess\s*(\.|\[\s*['"`])binding(['"`]\s*\])?\s*\(/,
      /\bprocess\s*(\.|\[\s*['"`])dlopen(['"`]\s*\])?\s*\(/,
      /\b(?:require|import|_load)\s*(?:\?\.\s*)?\([^)\n]{0,200}\.node['"`]\s*\)/,
    ],
  },
  {
    key: 'sensitiveTargets',
    label: 'Sensitive credential/file targeting',
    severity: 5,
    // A credential has to be accessed, not mentioned. Naming one is common in
    // help text, denylist regexes, syntax grammars and config filename lists,
    // so a path counts only where the line also does something with a path.
    // The env forms are already access-shaped and need no context.
    patterns: [
      { match: /\.npmrc\b/, context: PATH_ACCESS },
      { match: /\.ssh\//, context: PATH_ACCESS },
      { match: /\bid_rsa\b/, context: PATH_ACCESS },
      { match: /\.aws\/credentials\b/, context: PATH_ACCESS },
      { match: /(?:\.config\/gcloud\/|application_default_credentials)/, context: PATH_ACCESS },
      { match: /\.docker\/config\.json\b/, context: PATH_ACCESS },
      { match: /\.kube\/config\b/, context: PATH_ACCESS },
      { match: /\.git-credentials\b/, context: PATH_ACCESS },
      { match: /\.netrc\b/, context: PATH_ACCESS },
      { match: /\b_authToken\b/, context: PATH_ACCESS },
      // Environment/propagation credentials, the set a worm can spread or pivot
      // on. Cloud-infra keys sit here alongside AWS; a package's own service
      // key (FIGMA_TOKEN, OPENAI_API_KEY) is credential-shaped but not this, and
      // is caught one tier down by CREDENTIAL_ENV_PATTERN.
      /\bprocess\.env\.(GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|GITLAB_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET)\b/,
      /\bprocess\.env\[\s*['"](GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|GITLAB_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET)['"]\s*\]/,
    ],
  },
];

// A path anchored inside the package resolves to a file the walk already
// read, so it is not a loss of visibility. Excluded from UNRESOLVED_REQUIRE.
const LOCAL_SPECIFIER = /__dirname|__filename|['"`]\.\.?\//;

// A require whose specifier is not a literal, after lib/normalize.js has
// folded what it can. The module is then unknown, and so is every capability
// it brings: `require(deobfuscate(payload))` would otherwise report nothing,
// reading like an inert package. Excludes a property named require and
// webpack's `__webpack_require__`, neither of which is the loader.
const UNRESOLVED_REQUIRE = /(?<![.$\w])(?:require|import)\s*\(\s*(?!['"`]|\s*\))[^)\n]{0,200}\)/;

// TypeScript the compiler erases, and so cannot acquire a capability at
// runtime: a declaration file emits nothing, and `import type` is erased
// wherever it appears. Only the syntax is blanked, never the file, because
// `require('./x.d.ts')` does execute; call sites in one still count.
const DECLARATION_FILE_PATTERN = /\.d\.[cm]?ts$/i;

const ERASED_SYNTAX = [
  {
    key: 'typeOnlyImport',
    declarationFileOnly: false,
    pattern: /(?<![.\w$])(?:import|export)\s+type\b[^;]{0,400}?\bfrom\s*(['"])[^'"\n]*\1/g,
  },
  {
    key: 'declarationImport',
    declarationFileOnly: true,
    pattern: /(?<![.\w$])(?:import|export)\b[^;]{0,400}?\bfrom\s*(['"])[^'"\n]*\1/g,
  },
  // `import net = require('net')`, which is not valid JavaScript and so
  // cannot run even if the declaration file is require()d.
  {
    key: 'declarationImportEquals',
    declarationFileOnly: true,
    pattern: /(?<![.\w$])import\s+[A-Za-z_$][\w$]*\s*=\s*require\s*\(\s*(['"])[^'"\n]*\1\s*\)/g,
  },
  // `typeof import('x')` is a TypeScript type query, never a runtime import,
  // so it must not read as acquiring the module's capability. @types/node
  // writes `"child_process": typeof import("child_process")`, which otherwise
  // credited every consumer of @types with process execution.
  {
    key: 'typeofImport',
    declarationFileOnly: false,
    pattern: /\btypeof\s+import\s*\(\s*(['"])[^'"\n]*\1\s*\)/g,
  },
  // In a declaration file `import('x')` is always a type position (there is no
  // runtime to import into); a real dynamic import lives in a .ts/.js file,
  // where it still counts.
  {
    key: 'declarationDynamicImport',
    declarationFileOnly: true,
    pattern: /(?<![.\w$])import\s*\(\s*(['"])[^'"\n]*\1\s*\)/g,
  },
];

// Extracted as evidence, not a pass/fail category. A URL literal ends at
// whitespace, a quote, a paren, a backslash (an escape, not part of the URL),
// an angle bracket, or a comma joining two URLs in one config string.
const URL_PATTERN = /https?:\/\/[a-zA-Z0-9\-._~%]+(?::[0-9]+)?[^\s'"`)<>,\\]*/g;

// Sentence punctuation glued to a URL in an error message.
const ENDPOINT_TRAILING_JUNK = /[.,;:!?]+$/;

// A host has to look like one; `https://.` matched URL_PATTERN. Names need a
// dot, and localhost, IPv4 and bracketed IPv6 are the three that do not.
const ENDPOINT_HOST =
  /^https?:\/\/(?:localhost|\[[0-9A-Fa-f:.]+\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[a-zA-Z0-9\-_~%]+(?:\.[a-zA-Z0-9\-_~%]+)+)/;
const ENV_VAR_PATTERN = /process\.env\.([A-Za-z_][A-Za-z0-9_]*)|process\.env\[\s*['"]([^'"]+)['"]\s*\]/g;

// Very long lines are the shape of packed payloads. Build output is excluded
// (see looksLikeBuildArtifact), or a third of popular packages would trip it.
const LONG_LINE_THRESHOLD = 500;

// One long line is a data blob or a big regex. Several are minification.
const MIN_LONG_LINES_FOR_OBFUSCATION = 3;

// Long lines that are one syntactic thing rather than many statements packed
// together: long because of what they hold, not because anything is hidden.
// Statement density was tried as a general discriminator and does not work,
// since terser collapses statements into comma sequences.
const GENERATED_LONG_LINE = [
  // tsc CommonJS re-export chain: exports.a = exports.b = exports.c = ...
  /^(\s*exports\.[A-Za-z_$][\w$]*\s*=\s*){4,}/,
  // ESM barrel: export { A, B, C, ... } or export * from '...'
  /^\s*export\s*(\*|\{)[^;]*;?\s*$/,
  // A single named regex literal.
  /^\s*(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*\/.*\/[dgimsuvy]*\s*;?\s*$/,
];

// A newly read env var worth failing a build over. Matched on the noun that
// denotes a secret, never on a vendor prefix: npm passes its own config to
// install scripts as npm_config_*, and GITHUB_WORKSPACE and AWS_REGION are
// ordinary CI settings. A bare _KEY suffix is not enough either, since
// DOTENV_KEY, CACHE_KEY and PARTITION_KEY all end that way.
const CREDENTIAL_ENV_PATTERN =
  /(^|_)(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|APIKEY|AUTH)(_|$)|(^|_)(PRIVATE|SECRET|ACCESS|API|SIGNING|ENCRYPTION|AUTH)_KEY(_|$)|_TOKEN$|_SECRET$/i;

// An executable in `bin` has no reason to carry a .js extension: the shell
// runs it through its shebang. One in nine packages that ship an executable
// points `bin` at a file an extension filter skips.
const EXECUTABLE_SHEBANG_PATTERN = /^#!.*\b(node|nodejs|bun|deno|ts-node|tsx)\b/;

// Enough for any interpreter line, small enough that a large extension-less
// data file costs one short read rather than a full load.
const SHEBANG_PROBE_BYTES = 256;

// A lifecycle command runs at install time but lives in package.json, so the
// directory walk never reaches it. It is a shell line rather than JavaScript,
// so it is matched against both the categories above, which is what reaches
// an inline `node -e` payload, and these.
const INSTALL_COMMAND_RULES = [
  { key: 'network', pattern: /(^|[\s;&|(])(curl|wget|nc|ncat|scp|sftp)\s/ },
  { key: 'network', pattern: /https?:\/\/[^\s'"`;|)]+/ },
  // A real pipe into a shell, the download-and-run shape. `a || bash b` is a
  // fallback, not a pipe, and was this rule's only match across the corpus.
  { key: 'exec', pattern: /(?<!\|)\|(?!\|)\s*(sudo\s+)?(ba|z|k|da)?sh\b/ },
  // Handing a script to a shell is execution however it is reached.
  { key: 'exec', pattern: /(^|[;&|]\s*)(sudo\s+)?(ba|z|k|da)?sh\s+[^\s;&|]+/ },
  // `node -e` evaluates a string, which is both this category's definition
  // and where an inline payload would live.
  { key: 'dynamicEval', pattern: /\bnode\s+(-e|--eval|-p|--print)\b/ },
  { key: 'dynamicEval', pattern: /\bbase64\s+(-d|--decode|-D)\b/ },
];

// A postinstall that only prints a message cannot execute anything, but it
// still counted as running code at install time, one leg of the worm pattern.
// Chaining or redirection disqualifies it: `echo x > ~/.profile` writes a
// file and `echo x | sh` executes one.
const INERT_INSTALL_COMMAND = /^\s*(?::|true|echo(\s+[^;&|<>`$()]*)?)\s*$/;

const LIFECYCLE_SCRIPT_KEYS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];

// The scripts that run for a consumer installing from the registry. Per npm's
// documented behavior `prepare` and `prepublish` run only for local
// development or a git-URL dependency, so treating them like `postinstall`
// put false CRITICAL flags on glob and axios for shipping a tshy build step.
// It also tracks the real attack surface: Shai-Hulud used postinstall, its V2
// switched to preinstall so the payload runs even if the install then fails.
const INSTALL_TRIGGERING_SCRIPT_KEYS = ['preinstall', 'install', 'postinstall'];

module.exports = {
  CATEGORIES,
  ENDPOINT_TRAILING_JUNK,
  ENDPOINT_HOST,
  DECLARATION_FILE_PATTERN,
  ERASED_SYNTAX,
  MIN_LONG_LINES_FOR_OBFUSCATION,
  URL_PATTERN,
  ENV_VAR_PATTERN,
  CREDENTIAL_ENV_PATTERN,
  LONG_LINE_THRESHOLD,
  GENERATED_LONG_LINE,
  LIFECYCLE_SCRIPT_KEYS,
  INSTALL_TRIGGERING_SCRIPT_KEYS,
  INSTALL_COMMAND_RULES,
  INERT_INSTALL_COMMAND,
  UNRESOLVED_REQUIRE,
  LOCAL_SPECIFIER,
  EXECUTABLE_SHEBANG_PATTERN,
  SHEBANG_PROBE_BYTES,
};
