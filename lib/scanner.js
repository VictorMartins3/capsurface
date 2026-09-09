'use strict';

const fs = require('fs');
const path = require('path');
const {
  CATEGORIES,
  URL_PATTERN,
  ENV_VAR_PATTERN,
  LONG_LINE_THRESHOLD,
  MIN_LONG_LINES_FOR_OBFUSCATION,
  LIFECYCLE_SCRIPT_KEYS,
  INSTALL_TRIGGERING_SCRIPT_KEYS,
  CREDENTIAL_ENV_PATTERN,
} = require('./categories');
const { RULES_VERSION } = require('./rules-version');

const SOURCE_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.ts', '.tsx', '.jsx']);

// Only skip a nested node_modules, whose packages are scanned in their own
// right, and .git. Nothing else.
//
// This deliberately does not skip test/, docs/ or examples/, which an
// earlier version did. Ignoring test directories is a reasonable habit when
// scanning your own repository, where test code is noisy and trusted. It is
// the wrong assumption for a published tarball: anything shipped inside one
// can be require()d, so directory names carry no authority. It is also
// exactly where the event-stream attack hid, the payload lived in
// flatmap-stream's test directory specifically because that directory was
// absent from the GitHub repo, so the published tarball differed from the
// source anyone would review. Verified: with test/ skipped, a fixture built
// to that shape passed the gate with exit 0.
const SKIP_DIRS = new Set(['node_modules', '.git']);

// The input to this scanner is, by definition, untrusted: the whole point
// is inspecting code an attacker may control. Nothing previously bounded
// how large a single file this scanner would read fully into memory and
// run the regex engine over. A package could ship one abnormally large
// source file specifically to stall or exhaust a CI runner's memory,
// independent of anything the file's content actually does. 15 MB is well
// above any legitimate single hand-authored or bundled JS file seen across
// the real corpora this tool was benchmarked against (the largest observed
// was under 2 MB); a file above this is skipped rather than read, and that
// skip is recorded in the manifest (`skippedLargeFiles`) so it's visible
// to a reviewer rather than silently reducing coverage.
const MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024;

// Paths that look like build/bundle output rather than hand-authored source.
// Legitimate packages routinely ship a minified UMD/CJS/ESM bundle alongside
// their real source (lodash's core.min.js, axios's dist/axios.min.js, etc.);
// those files are *expected* to have very long lines and shouldn't, on their
// own, read as "this package just got obfuscated". Confirmed against a
// corpus of 118 real installed packages: without this exclusion, roughly a
// third of them tripped the obfuscation flag purely from ordinary bundled
// output. We still run full capability pattern matching on these files
// (a malicious bundle can still literally contain `require('https')` etc.);
// this only suppresses the long-line-based obfuscation signal for them.
// `dist` and `build` take a suffix in the wild: uuid ships dist-node/,
// others use dist-esm/, dist-web/, dist-types/. Matching only the bare name
// left those reading as hand-authored source, so an ordinary minified build
// output tripped the obfuscation signal.
const BUILD_ARTIFACT_PATH =
  /(^|[\\/])(dist(-[a-z0-9]+)?|build(-[a-z0-9]+)?|umd|cjs|esm|lib-esm|vendor)([\\/]|$)|[.\-]min\.[jt]sx?$|\.bundle\.[jt]sx?$/i;

function looksLikeBuildArtifact(relPath) {
  return BUILD_ARTIFACT_PATH.test(relPath);
}

function walk(dir, files) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, files);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      if (SOURCE_EXTENSIONS.has(ext)) files.push(full);
    }
  }
}

/**
 * Blank `//` and `/* *\/` comments to spaces, preserving line/column
 * offsets exactly. String, template-literal, and regex-literal contents
 * are left untouched: patterns must match inside strings (e.g.
 * `require('child_process')`), and a regex literal can legally contain a
 * quote (`/['"]/`) that must not be mistaken for a string delimiter.
 *
 * Hand-rolled character scanner, not a real parser. Regex-vs-division is
 * ambiguous in JS without full parsing (both use a bare `/`); resolved via
 * the last significant token, not just the last character:
 *   - after an identifier/number/string/regex/`]` -> division (a value was
 *     just produced: `total / 2`, `arr[0] / 2`, `"x" / 2`).
 *   - after `)` -> depends on the kind of `)`. A call/group close
 *     (`foo() / 2`) is a value, so division; a control-flow condition
 *     close (`if (x) /re/.test(y)`) is not, so a regex is allowed.
 *     Tracked via a paren stack recording, at each `(`, whether the
 *     preceding token was `if`/`while`/`for`/`switch`/`catch`/`with`.
 *   - after an expression-expecting keyword (`return`, `typeof`, `new`,
 *     `else`, `case`, etc, see REGEX_PERMITTING_KEYWORDS) -> regex.
 *   - after any other punctuation/operator, or at start-of-input -> regex.
 *
 * Known gap: `${...}` template interpolation is treated as opaque string
 * content, so a comment inside it won't be blanked.
 */
function blankComments(content) {
  const out = [];
  const NORMAL = 0;
  const LINE_COMMENT = 1;
  const BLOCK_COMMENT = 2;
  const STRING = 3;
  const REGEX = 4;
  let state = NORMAL;
  let quoteChar = '';
  let regexInClass = false;
  let lastSignificant = ''; // last non-whitespace char seen in NORMAL state
  let wordBuf = ''; // accumulates the identifier currently being scanned
  let lastWord = ''; // most recently completed identifier/keyword token
  let lastParenWasControlFlow = false; // was the most recent ')' a control-flow condition close?
  const parenStack = [];
  const VALUE_CONTEXT = /[A-Za-z0-9_$\]]/; // last char implies division follows, not regex
  // Fast paths for the two checks that run on every character of every
  // scanned file (profiled: together ~16% of total scan time on a 462MB
  // real-world corpus, entirely regex-engine overhead for a check simple
  // enough to do with arithmetic). ASCII-only, matching what the
  // equivalent /[A-Za-z0-9_$]/ and /\s/ regexes actually covered for real
  // source code; a non-ASCII identifier character (rare in practice, and
  // already outside what those regexes matched) falls through to the plain
  // punctuation path, which is a pre-existing, harmless approximation for
  // this heuristic scanner, not a new gap introduced here.
  const isIdentCharCode = (code) =>
    (code >= 48 && code <= 57) || // 0-9
    (code >= 65 && code <= 90) || // A-Z
    (code >= 97 && code <= 122) || // a-z
    code === 95 || // _
    code === 36; // $
  const isAsciiSpaceCode = (code) => code === 32 || (code >= 9 && code <= 13); // space, \t\n\v\f\r
  const CONTROL_FLOW_KEYWORDS = new Set(['if', 'while', 'for', 'switch', 'catch', 'with']);
  const REGEX_PERMITTING_KEYWORDS = new Set([
    'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void',
    'throw', 'do', 'else', 'yield', 'case', 'default', 'await',
  ]);

  function regexAllowed() {
    if (lastSignificant === ')') return lastParenWasControlFlow;
    if (VALUE_CONTEXT.test(lastSignificant)) return REGEX_PERMITTING_KEYWORDS.has(lastWord);
    return true; // operator, opening punctuation, or start-of-input
  }

  for (let i = 0; i < content.length; i++) {
    const c = content[i];
    const next = content[i + 1];

    if (state === LINE_COMMENT) {
      if (c === '\n') {
        state = NORMAL;
        out.push('\n');
      } else {
        out.push(' ');
      }
      continue;
    }
    if (state === BLOCK_COMMENT) {
      if (c === '*' && next === '/') {
        out.push('  ');
        i++;
        state = NORMAL;
      } else {
        out.push(c === '\n' ? '\n' : ' ');
      }
      continue;
    }
    if (state === STRING) {
      out.push(c);
      if (c === '\\') {
        // Preserve the escaped character verbatim so we don't misread an
        // escaped quote as the string terminator.
        if (next !== undefined) {
          out.push(next);
          i++;
        }
        continue;
      }
      if (c === quoteChar) {
        state = NORMAL;
        lastSignificant = 'x'; // a completed string is a value, like an identifier
        // A stale lastWord from before this string must not leak through:
        // regexAllowed() checks REGEX_PERMITTING_KEYWORDS.has(lastWord)
        // whenever lastSignificant is alnum, and without this reset
        // `return "foo" / 2` would wrongly reuse "return" from before the
        // string and misjudge the following `/` as a regex start.
        lastWord = '';
      }
      continue;
    }
    if (state === REGEX) {
      out.push(c);
      if (c === '\\') {
        if (next !== undefined) {
          out.push(next);
          i++;
        }
        continue;
      }
      if (c === '[') {
        regexInClass = true;
      } else if (c === ']') {
        regexInClass = false;
      } else if (c === '/' && !regexInClass) {
        state = NORMAL;
        lastSignificant = 'x'; // a completed regex literal is a value
        lastWord = ''; // same stale-keyword hazard as the STRING case above
      }
      continue;
    }
    // NORMAL
    if (isIdentCharCode(content.charCodeAt(i))) {
      wordBuf += c;
      out.push(c);
      lastSignificant = c;
      continue;
    }
    // c is not an identifier character: finalize any pending word first.
    if (wordBuf) {
      lastWord = wordBuf;
      wordBuf = '';
    }
    if (c === '/' && next === '/') {
      state = LINE_COMMENT;
      out.push('  ');
      i++;
      continue;
    }
    if (c === '/' && next === '*') {
      state = BLOCK_COMMENT;
      out.push('  ');
      i++;
      continue;
    }
    if (c === '(') {
      parenStack.push(CONTROL_FLOW_KEYWORDS.has(lastWord));
      // Consume lastWord: without this reset, a second `(` right after the
      // first (`if ((a + b) / c)`) would reuse the stale 'if' for the
      // inner paren too, wrongly marking it a control-flow close.
      lastWord = '';
      out.push(c);
      lastSignificant = c;
      continue;
    }
    if (c === ')') {
      lastParenWasControlFlow = parenStack.length ? parenStack.pop() : false;
      out.push(c);
      lastSignificant = ')';
      continue;
    }
    if (c === '/' && regexAllowed()) {
      state = REGEX;
      out.push(c);
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      state = STRING;
      quoteChar = c;
      out.push(c);
      continue;
    }
    out.push(c);
    if (!isAsciiSpaceCode(content.charCodeAt(i))) lastSignificant = c;
  }
  return out.join('');
}

function initCapabilities() {
  const caps = {};
  for (const cat of CATEGORIES) {
    caps[cat.key] = { present: false, evidence: [] };
  }
  caps.network.endpoints = [];
  caps.env.vars = [];
  caps.lifecycleScripts = {
    present: false,
    installTriggering: false,
    scripts: {},
  };
  caps.obfuscationSignal = { present: false, evidence: [] };
  caps.skippedLargeFiles = { present: false, count: 0, files: [] };
  return caps;
}

// `pattern` records which rule matched. Without it a reviewer asking "why
// was this flagged" has to re-derive the answer by eye, and attributing a
// false positive to a specific rule across a large corpus is guesswork.
function addEvidence(list, file, lineNo, line, pattern, max = 5) {
  if (list.length >= max) return;
  const snippet = line.trim().slice(0, 200);
  const entry = { file, line: lineNo, snippet };
  if (pattern) entry.pattern = String(pattern);
  list.push(entry);
}

function scanFileContent(relPath, content, caps) {
  const longLines = [];
  const codeOnly = blankComments(content);
  const originalLines = content.split('\n');
  const codeLines = codeOnly.split('\n');
  const isBuildArtifact = looksLikeBuildArtifact(relPath);

  for (let i = 0; i < codeLines.length; i++) {
    const codeLine = codeLines[i];
    const originalLine = originalLines[i] !== undefined ? originalLines[i] : codeLine;
    const lineNo = i + 1;

    // Measured on the comment-blanked line with whitespace trimmed off.
    // Blanking preserves length so columns stay accurate, which means a
    // 592-character JSDoc line becomes 592 spaces and used to count as a
    // long line: documentation was being reported as obfuscation. Trimming
    // collapses a blanked comment to nothing while leaving real minified
    // code untouched.
    const codeLength = codeLine.trim().length;
    if (!isBuildArtifact && codeLength > LONG_LINE_THRESHOLD) {
      longLines.push({ lineNo, codeLength });
    }

    for (const cat of CATEGORIES) {
      for (const pattern of cat.patterns) {
        if (pattern.test(codeLine)) {
          caps[cat.key].present = true;
          addEvidence(caps[cat.key].evidence, relPath, lineNo, originalLine, pattern);
          break;
        }
      }
    }

    let m;
    URL_PATTERN.lastIndex = 0;
    while ((m = URL_PATTERN.exec(codeLine)) !== null) {
      if (caps.network.endpoints.length < 20 && !caps.network.endpoints.includes(m[0])) {
        caps.network.endpoints.push(m[0]);
      }
    }
    ENV_VAR_PATTERN.lastIndex = 0;
    while ((m = ENV_VAR_PATTERN.exec(codeLine)) !== null) {
      const name = m[1] || m[2];
      if (name && caps.env.vars.length < 40 && !caps.env.vars.includes(name)) {
        caps.env.vars.push(name);
      }
    }
  }

  // Minification produces many long lines, or a whole file on one line.
  // A single long line in an otherwise normal file is almost always data or
  // one big regex: eslint embeds a base64 icon in an HTML template,
  // js-tokens is one 632-character tokenizer regex. Both were being
  // reported as obfuscated. Requiring either several long lines or a file
  // whose lines average very long keeps real packed payloads, which are
  // never one stray line in otherwise ordinary source.
  if (longLines.length) {
    const avgLineLength = codeOnly.length / Math.max(1, codeLines.length);
    if (longLines.length >= MIN_LONG_LINES_FOR_OBFUSCATION || avgLineLength > LONG_LINE_THRESHOLD) {
      caps.obfuscationSignal.present = true;
      for (const l of longLines.slice(0, 3)) {
        addEvidence(
          caps.obfuscationSignal.evidence,
          relPath,
          l.lineNo,
          `<line of length ${l.codeLength}>`,
          null,
          3
        );
      }
    }
  }
}

// Distinguishes "no package.json here" (unremarkable, e.g. `scan` invoked
// on an arbitrary directory) from "package.json exists but is not valid
// JSON" (which a real published npm package cannot have, since the
// registry validates it at publish time; unparseable is a real anomaly
// worth surfacing, not the same as absent).
function readPackageJson(dir) {
  const pkgPath = path.join(dir, 'package.json');
  let raw;
  try {
    raw = fs.readFileSync(pkgPath, 'utf8');
  } catch (e) {
    return { data: null, malformed: false };
  }
  try {
    return { data: JSON.parse(raw), malformed: false };
  } catch (e) {
    return { data: null, malformed: true };
  }
}

function computeRisk(caps) {
  let score = 0;
  const flags = [];
  for (const cat of CATEGORIES) {
    if (caps[cat.key].present) score += cat.severity;
  }
  if (caps.lifecycleScripts.installTriggering) {
    score += 4;
  } else if (caps.lifecycleScripts.present) {
    // Build-time-only script (prepare/prepublish): doesn't run for a normal
    // registry install, so it's weighted far lower than an install-
    // triggering script, but still worth a small amount of signal (e.g. the
    // package is pulled via a git dependency somewhere in the tree).
    score += 1;
  }
  if (caps.obfuscationSignal.present) score += 3;

  const hasInstallTriggering = caps.lifecycleScripts.installTriggering;
  const hasBuildTimeOnly = caps.lifecycleScripts.present && !hasInstallTriggering;
  const hasNetwork = caps.network.present;
  const hasSensitive = caps.sensitiveTargets.present;
  const hasExec = caps.exec.present;
  // Credential-shaped env access, not env access of any kind. esbuild's
  // postinstall downloads its own binary from the npm registry and reads
  // ESBUILD_BINARY_PATH, which is install-time code plus network plus env,
  // the shape of the worm pattern without its substance. The worm reads
  // .npmrc and NPM_TOKEN. Requiring credential shape keeps esbuild at HIGH
  // (install script plus process execution, worth an allowlist decision)
  // instead of calling it a worm.
  const hasCredentialEnv = (caps.env.vars || []).some((v) => CREDENTIAL_ENV_PATTERN.test(v));
  const hasCredentialAccess = hasSensitive || hasCredentialEnv;

  if (hasInstallTriggering && hasNetwork && hasCredentialAccess) {
    score += 10;
    flags.push(
      'CRITICAL: install-time lifecycle script (preinstall/install/postinstall) combined with ' +
        'network access and credential/env access, matching the self-propagating supply-chain ' +
        'worm pattern (e.g. Shai-Hulud).'
    );
  } else if (hasBuildTimeOnly && hasNetwork && hasCredentialAccess) {
    flags.push(
      'MEDIUM: build-time script (prepare/prepublish) combined with network and credential/env ' +
        'access. This script does NOT run for a normal registry install of this package as a ' +
        'dependency, only for local development or a git-URL dependency, so it is lower risk ' +
        'than an install-triggering script, but worth a look if this package is pulled via git.'
    );
  }
  if (hasInstallTriggering && hasExec) {
    flags.push('HIGH: install-time lifecycle script combined with process execution.');
  }
  if (hasSensitive && hasNetwork) {
    flags.push('HIGH: code reads credential-like paths/vars and also has network access (possible exfiltration path).');
  }
  if (caps.obfuscationSignal.present) {
    flags.push('MEDIUM: minified/obfuscated-looking source (very long lines); static analysis coverage is reduced here.');
  }
  if (caps.dynamicEval.present) {
    flags.push('MEDIUM: dynamic code execution (eval/new Function) can hide capabilities from static analysis entirely.');
  }
  if (caps.skippedLargeFiles.present) {
    score += 2;
    flags.push(
      'MEDIUM: one or more source files exceeded the size limit for scanning and were skipped. ' +
        'Static analysis coverage is reduced for this package. See skippedLargeFiles for which files.'
    );
  }

  return { score, flags };
}

/**
 * Scan a single package directory (e.g. a node_modules/<pkg> folder, or a
 * package source checkout) and return a capability manifest.
 */
function scanPackageDir(dir) {
  const { data: pkgJson, malformed: malformedPackageJson } = readPackageJson(dir);
  const name = (pkgJson && pkgJson.name) || path.basename(dir);
  const version = (pkgJson && pkgJson.version) || '0.0.0-unknown';

  const caps = initCapabilities();

  if (pkgJson && pkgJson.scripts) {
    for (const key of LIFECYCLE_SCRIPT_KEYS) {
      if (pkgJson.scripts[key]) {
        caps.lifecycleScripts.present = true;
        caps.lifecycleScripts.scripts[key] = pkgJson.scripts[key];
        if (INSTALL_TRIGGERING_SCRIPT_KEYS.includes(key)) {
          caps.lifecycleScripts.installTriggering = true;
        }
      }
    }
  }

  const files = [];
  walk(dir, files);
  for (const file of files) {
    const relPath = path.relative(dir, file);
    try {
      const st = fs.statSync(file);
      if (st.size > MAX_FILE_SIZE_BYTES) {
        caps.skippedLargeFiles.present = true;
        caps.skippedLargeFiles.count++;
        // `.files` is capped for evidence display; `.count` above is the
        // true total and is what sourceFilesSkipped reports. Using
        // `.files.length` there would silently undercount past the cap.
        if (caps.skippedLargeFiles.files.length < 10) {
          caps.skippedLargeFiles.files.push({ file: relPath, sizeBytes: st.size });
        }
        continue;
      }
    } catch (e) {
      continue;
    }
    let content;
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch (e) {
      continue;
    }
    scanFileContent(relPath, content, caps);
  }

  let { score, flags } = computeRisk(caps);
  if (malformedPackageJson) {
    // A published npm package always has valid package.json (the registry
    // validates it at publish time), so a package.json present but not
    // parseable as JSON is not expected noise, it is an anomaly worth a
    // reviewer's attention.
    score += 2;
    flags = [...flags, 'MEDIUM: package.json exists but is not valid JSON.'];
  }

  return {
    schemaVersion: 3,
    rulesVersion: RULES_VERSION,
    name,
    version,
    scannedAt: new Date().toISOString(),
    sourceFilesScanned: files.length - caps.skippedLargeFiles.count,
    sourceFilesSkipped: caps.skippedLargeFiles.count,
    malformedPackageJson,
    capabilities: caps,
    riskScore: score,
    riskFlags: flags,
  };
}

module.exports = { scanPackageDir, walk, blankComments, looksLikeBuildArtifact };
