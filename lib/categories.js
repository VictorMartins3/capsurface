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

// Doing something with a path, as opposed to naming one. Used to separate a
// credential file being opened from a credential file being talked about.
const PATH_ACCESS =
  /\b(?:readFile|writeFile|appendFile|createReadStream|createWriteStream|open|unlink|stat|access|realpath|copyFile|rename|chmod|exists)[A-Za-z]*\s*\(|\bfs\w*\.\w+\s*\(|\bpath\.(?:join|resolve|normalize)\s*\(|\b(?:homedir|userInfo|tmpdir)\s*\(|\bprocess\.env\.(?:HOME|USERPROFILE)\b/;

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
    //
    // `.connect(` / `.createConnection(` were removed for the same reason,
    // applying the rule already used for exec: key on importing the module,
    // not on a call site whose name is shared with unrelated APIs. Across
    // 3,079 real package installs it fired on 84 packages and was the sole
    // evidence for only 6, of which inquirer's `this.process.connect()` and
    // rxjs's `connectable.connect()` are not network at all, and TypeScript's
    // inspector `session.connect()` was being reported as network access in
    // packages that had it anyway. The one thing it caught that the module
    // list missed was `http2.connect()`, so http2 was added above, which is
    // a real gap this analysis found.
    patterns: [
      /\brequire\(\s*['"](node:)?(https?|http2|net|dgram|tls|dns)['"]\s*\)/,
      /\bfrom\s+['"](node:)?(https?|http2|net|dgram|tls|dns)['"]/,
      /\bawait\s+fetch\s*\(/,
      /\bfetch\s*\(\s*['"`]https?:\/\//,
      /\b(?:globalThis|window|self)\.fetch\s*\(/,
      /\bnew\s+XMLHttpRequest\b/,
      /\bnew\s+WebSocket\s*\(/,
      /\brequire\(\s*['"](axios|node-fetch|undici|got|superagent|request)['"]\s*\)/,
      /\bfrom\s+['"](axios|node-fetch|undici|got|superagent|request)['"]/,
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
    // `new Function("return this")` is the standard way to reach the global
    // object across environments, emitted by webpack, babel and core-js into
    // almost every bundle. The argument is a constant with no input, so it
    // executes nothing an attacker chose. It was the whole of the dynamic-eval
    // evidence for hundreds of packages in a 10,696 package sample, each one
    // carrying a MEDIUM flag saying static analysis coverage was reduced.
    patterns: [
      /\beval\s*\(/,
      /\bnew\s+Function\s*\((?!\s*(['"`])return (this|globalThis)\1\s*\))/,
      /\bvm\.(runIn|Script)\b/,
    ],
  },
  {
    key: 'nativeFfi',
    label: 'Native / FFI code',
    severity: 3,
    // Keyed on loading native code, not on a string that ends in ".node".
    // The bare-suffix rule was every one of this category's sole-evidence
    // matches across 1,849 packages, and it was matching comparisons rather
    // than loads: node-addon-api's `path.basename(item) !== 'nothing.node'`,
    // bunchee's `if (!source.endsWith('.node'))`. Same rule already applied
    // to exec and to `.connect(`: match the acquisition, not a name.
    patterns: [
      /\brequire\(\s*['"](ffi-napi|bindings|node-gyp-build|node-gyp-build-optional-packages)['"]\s*\)/,
      /\bprocess\.binding\s*\(/,
      /\bprocess\.dlopen\s*\(/,
      /\brequire\s*\([^)\n]{0,200}\.node['"`]\s*\)/,
    ],
  },
  {
    key: 'sensitiveTargets',
    label: 'Sensitive credential/file targeting',
    severity: 5,
    // A credential must appear as an actual access, not a mention. That rule
    // was already applied to env vars, which had been matching help text and
    // shipped test assertions; the same thing turned out to be true of file
    // paths. Across 11,615 published packages, 34 of the 75 with this
    // capability had no access at all: shikiji's syntax grammar listing
    // ".ssh/config" as a file type, nx printing '... in the project
    // ".npmrc"', denylist regexes like /^\.npmrc$/i and globs like
    // "**/id_rsa", a placeholder "C:/Users/your-name/.ssh/id_rsa", and a
    // security scanner's own documentation of the attack it detects. A
    // routine vite 5 to 8 upgrade failed the gate on the string ".npmrc"
    // inside a bundled list of config filenames.
    //
    // So a path counts when the line also does something with a path. The
    // cost is a path named on one line and opened on another, which
    // line-scoped matching cannot see either way; the filesystem capability
    // still reports the access itself.
    patterns: [
      { match: /\.npmrc\b/, context: PATH_ACCESS },
      { match: /\.ssh\//, context: PATH_ACCESS },
      { match: /\bid_rsa\b/, context: PATH_ACCESS },
      { match: /\.aws\/credentials\b/, context: PATH_ACCESS },
      { match: /\.netrc\b/, context: PATH_ACCESS },
      { match: /\b_authToken\b/, context: PATH_ACCESS },
      /\bprocess\.env\.(GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\b/,
      /\bprocess\.env\[\s*['"](GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)['"]\s*\]/,
    ],
  },
];

// TypeScript syntax that the compiler erases, and so cannot acquire a
// capability at runtime. A declaration file emits no JavaScript at all, and
// `import type` is erased wherever it appears.
//
// Measured by scanning 5,761 real packages with and without this pass: 23
// were credited with a capability they do not have (16 network, 5 process
// execution, 2 filesystem). typescript read as having process execution
// because of `import { ChildProcess } from 'child_process'` in a .d.ts;
// lerna's entire process-execution evidence was five `import { ExecOptions }
// from "child_process"` lines in declaration files. No risk flag changed in
// that sample, so this is accuracy rather than noise reduction, but a
// capability a package does not have is the input every gate reads.
//
// Only the syntax is neutralized, not the file. Skipping declaration files
// outright would repeat the mistake SKIP_DIRS documents: `require('./x.d.ts')`
// does execute, Node loads an unknown extension as CommonJS, so require()
// calls and call sites inside a declaration file still count. ESM `import`
// and TypeScript's `import x = require()` are not things Node can execute
// from a .d.ts, which is what makes them safe to erase.
const DECLARATION_FILE_PATTERN = /\.d\.[cm]?ts$/i;

const ERASED_SYNTAX = [
  // `import type { X } from 'net'`, `export type { X } from 'net'`.
  {
    key: 'typeOnlyImport',
    declarationFileOnly: false,
    pattern: /(?<![.\w$])(?:import|export)\s+type\b[^;]{0,400}?\bfrom\s*(['"])[^'"\n]*\1/g,
  },
  // Any `import`/`export ... from` inside a declaration file.
  {
    key: 'declarationImport',
    declarationFileOnly: true,
    pattern: /(?<![.\w$])(?:import|export)\b[^;]{0,400}?\bfrom\s*(['"])[^'"\n]*\1/g,
  },
  // `import net = require('net')`, TypeScript's CommonJS import form. Not
  // valid JavaScript, so it cannot run even if the file is require()d.
  {
    key: 'declarationImportEquals',
    declarationFileOnly: true,
    pattern: /(?<![.\w$])import\s+[A-Za-z_$][\w$]*\s*=\s*require\s*\(\s*(['"])[^'"\n]*\1\s*\)/g,
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

// How many long lines a file needs before it reads as minified rather than
// as source that happens to contain one data blob or one large regex.
const MIN_LONG_LINES_FOR_OBFUSCATION = 3;

// Long lines that are one syntactic thing rather than many statements packed
// together. These are long because of what they contain, not because anyone
// hid anything, and they are what the obfuscation signal kept firing on when
// popular packages were upgraded across two years:
//
//   zod 3 -> 4      v3/types.cjs, a 1,011-character tsc re-export chain, and
//                   v3/types.js, a 682-character IPv6 regex literal
//   graphql 15 -> 17  index.mjs, a 1,723-character ESM barrel re-export
//
// Statement density was measured as a general discriminator instead and does
// not work: terser collapses consecutive statements into comma sequences, so
// a genuinely minified line can carry a single semicolon. These stay
// shape-specific on purpose.
const GENERATED_LONG_LINE = [
  // tsc CommonJS re-export chain: exports.a = exports.b = exports.c = ...
  /^(\s*exports\.[A-Za-z_$][\w$]*\s*=\s*){4,}/,
  // ESM barrel: export { A, B, C, ... } or export * from '...'
  /^\s*export\s*(\*|\{)[^;]*;?\s*$/,
  // A single named regex literal.
  /^\s*(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*\/.*\/[dgimsuvy]*\s*;?\s*$/,
];

// Env var names worth failing a build over when a dependency starts
// reading one it did not read before.
//
// Matched on words that denote a secret, not on vendor prefixes. An
// earlier version keyed on prefixes like NPM_, GITHUB_ and AWS_, which
// made geckodriver and edgedriver read as credential access and pushed
// them to CRITICAL: npm passes its own configuration to install scripts as
// npm_config_*, so npm_config_geckodriver_cdnurl matched NPM_. The same
// mistake would have counted GITHUB_WORKSPACE and AWS_REGION, both of
// which are ordinary CI configuration. A secret is indicated by the noun,
// TOKEN, SECRET, PASSWORD, KEY, CREDENTIAL, so match that instead.
// A bare _KEY suffix is not enough: DOTENV_KEY, CACHE_KEY and PARTITION_KEY
// all end that way and only the first is a secret, and gating on it made a
// routine dotenv 16 to 17 upgrade fail. Key forms have to name the kind of
// key.
const CREDENTIAL_ENV_PATTERN =
  /(^|_)(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|APIKEY|AUTH)(_|$)|(^|_)(PRIVATE|SECRET|ACCESS|API|SIGNING|ENCRYPTION|AUTH)_KEY(_|$)|_TOKEN$|_SECRET$/i;

// An executable shipped in `bin` has no reason to carry a .js extension: the
// shell runs it through its shebang. 158 of the 1,248 packages in a 8,009
// package sample that ship an executable point `bin` at a file the extension
// filter never reads, 12.7% of them, and that file is the code a consumer
// runs directly.
const EXECUTABLE_SHEBANG_PATTERN = /^#!.*\b(node|nodejs|bun|deno|ts-node|tsx)\b/;

// Bytes read from an extension-less file to look for that shebang. Enough
// for any real interpreter line, small enough that a large data file with no
// extension costs one short read rather than a full load.
const SHEBANG_PROBE_BYTES = 256;

// A lifecycle script's command is code that runs on install, but it lives in
// package.json rather than in a file, so walking the package never reaches
// it. Across 5,761 packages that hid the only command in the corpus that
// beacons out at install time: xhjxhjtestrce123 runs
// `curl http://<redacted>/?host=...` from both preinstall and postinstall,
// and its manifest recorded no network capability at all.
//
// The command is a shell line, not JavaScript, so it is matched against the
// JavaScript rules above (for `node -e "require(...)"`, which nx and four
// other packages in the corpus use) and against these shell-shaped ones.
// Measured on the same corpus: 115 packages run something at install time,
// and these rules fire on 3 of them, so they are close to free.
const INSTALL_COMMAND_RULES = [
  { key: 'network', pattern: /(^|[\s;&|(])(curl|wget|nc|ncat|scp|sftp)\s/ },
  { key: 'network', pattern: /https?:\/\/[^\s'"`;|)]+/ },
  // Anything piped into a shell is the download-and-run shape.
  { key: 'exec', pattern: /\|\s*(sudo\s+)?(ba|z|k|da)?sh\b/ },
  // `node -e` evaluates a string, which is the definition of this category
  // and is also where an inline payload would live.
  { key: 'dynamicEval', pattern: /\bnode\s+(-e|--eval|-p|--print)\b/ },
  { key: 'dynamicEval', pattern: /\bbase64\s+(-d|--decode|-D)\b/ },
];

// A lifecycle script that only prints a message cannot execute anything, but
// it still marked the package as running code at install time, which is one
// of the three legs of the worm pattern. aethercall's postinstall is
// `echo '\n(emoji) AetherCall installed! Run "npm run setup" ...'` and that
// alone made it CRITICAL. 5 of the 207 packages with install scripts in a
// 10,696 package sample are this shape, and two carried a flag off it.
//
// Any chaining or redirection disqualifies the command: `echo x > ~/.profile`
// writes a file and `echo x | sh` executes one.
const INERT_INSTALL_COMMAND = /^\s*(?::|true|echo(\s+[^;&|<>`$()]*)?)\s*$/;

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
  PATH_ACCESS,
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
  EXECUTABLE_SHEBANG_PATTERN,
  SHEBANG_PROBE_BYTES,
};
