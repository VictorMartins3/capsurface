'use strict';

const fs = require('fs');
const path = require('path');
const {
  CATEGORIES,
  URL_PATTERN,
  ENDPOINT_TRAILING_JUNK,
  ENDPOINT_HOST,
  ENV_VAR_PATTERN,
  LONG_LINE_THRESHOLD,
  GENERATED_LONG_LINE,
  MIN_LONG_LINES_FOR_OBFUSCATION,
  LIFECYCLE_SCRIPT_KEYS,
  INSTALL_TRIGGERING_SCRIPT_KEYS,
  CREDENTIAL_ENV_PATTERN,
  DECLARATION_FILE_PATTERN,
  ERASED_SYNTAX,
  INSTALL_COMMAND_RULES,
  INERT_INSTALL_COMMAND,
  EXECUTABLE_SHEBANG_PATTERN,
  SHEBANG_PROBE_BYTES,
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
// The directory names below are conventions for machine-generated output,
// taken from where the obfuscation signal actually fired across 11,615
// published packages rather than from guesswork: `bundles/`, `fesm2022/` and
// `esm2020/` are the Angular Package Format, `coverage/` is an istanbul
// report, `.yarn/releases/` is a vendored package manager, and `assets/`,
// `public/` and `docs/` are where packages ship minified third-party JS for
// a demo or doc site.
//
// `lib/` and `src/` are deliberately absent even though they were the two
// largest sources of unrecognised long lines. Both routinely hold
// hand-authored code, and a 39,000-character line in `src/` is exactly what
// this signal should still report.
const BUILD_ARTIFACT_PATH =
  /(^|[\\/])(dist(-[a-z0-9]+)?|build(-[a-z0-9]+)?|umd|cjs|esm|f?esm\d+|es|bundles|lib-esm|vendor|coverage|assets|public|docs?|\.yarn)([\\/]|$)|[.\-]min\.[jt]sx?$|\.bundle\.[jt]sx?$/i;

function looksLikeBuildArtifact(relPath) {
  return BUILD_ARTIFACT_PATH.test(relPath);
}

// Reads the first bytes of an extension-less file to see whether it is a
// script the shell will hand to node. See EXECUTABLE_SHEBANG_PATTERN.
function hasNodeShebang(file) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(SHEBANG_PROBE_BYTES);
    const read = fs.readSync(fd, buf, 0, SHEBANG_PROBE_BYTES, 0);
    const head = buf.toString('utf8', 0, read).split('\n', 1)[0];
    return EXECUTABLE_SHEBANG_PATTERN.test(head);
  } catch (e) {
    return false;
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch (e) { /* already gone */ }
    }
  }
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
      else if (ext === '' && hasNodeShebang(full)) files.push(full);
    }
  }
}

// Every path `bin` points at, which is the code a consumer runs directly.
// The shebang probe above already reaches most of them; this makes it a
// guarantee that does not depend on the file's contents, and covers a bin
// target with an extension the filter does not know.
function binTargets(dir, pkgJson) {
  const bin = pkgJson && pkgJson.bin;
  if (!bin) return [];
  const raw = typeof bin === 'string' ? [bin] : Object.values(bin);
  const out = [];
  for (const rel of raw) {
    if (typeof rel !== 'string' || !rel) continue;
    const full = path.resolve(dir, rel);
    // A bin entry is attacker-controlled text; keep it inside the package.
    if (full !== dir && !full.startsWith(dir + path.sep)) continue;
    try {
      if (fs.statSync(full).isFile()) out.push(full);
    } catch (e) { /* declared but not shipped */ }
  }
  return out;
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
  // Only comment characters ever differ from the input, so instead of
  // rebuilding the file one character at a time, record where the comments
  // are and splice blanks over those ranges at the end. Building a
  // million-element array and joining it was 28% of total scan time.
  const commentRanges = [];
  let commentStart = -1;
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
        commentRanges.push(commentStart, i);
      }
      continue;
    }
    if (state === BLOCK_COMMENT) {
      if (c === '*' && next === '/') {
        i++;
        state = NORMAL;
        commentRanges.push(commentStart, i + 1);
      }
      continue;
    }
    if (state === STRING) {
      if (c === '\\') {
        // Skip the escaped character so we don't misread an escaped quote as
        // the string terminator.
        if (next !== undefined) {
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
      if (c === '\\') {
        if (next !== undefined) {
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
      commentStart = i;
      i++;
      continue;
    }
    if (c === '/' && next === '*') {
      state = BLOCK_COMMENT;
      commentStart = i;
      i++;
      continue;
    }
    if (c === '(') {
      parenStack.push(CONTROL_FLOW_KEYWORDS.has(lastWord));
      // Consume lastWord: without this reset, a second `(` right after the
      // first (`if ((a + b) / c)`) would reuse the stale 'if' for the
      // inner paren too, wrongly marking it a control-flow close.
      lastWord = '';
      lastSignificant = c;
      continue;
    }
    if (c === ')') {
      lastParenWasControlFlow = parenStack.length ? parenStack.pop() : false;
      lastSignificant = ')';
      continue;
    }
    if (c === '/' && regexAllowed()) {
      state = REGEX;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      state = STRING;
      quoteChar = c;
      continue;
    }
    if (!isAsciiSpaceCode(content.charCodeAt(i))) lastSignificant = c;
  }
  if (state === LINE_COMMENT || state === BLOCK_COMMENT) {
    commentRanges.push(commentStart, content.length);
  }
  if (commentRanges.length === 0) return content;

  let result = '';
  let pos = 0;
  for (let k = 0; k < commentRanges.length; k += 2) {
    const from = commentRanges[k];
    const to = commentRanges[k + 1];
    result += content.slice(pos, from);
    result += blankRun(content.slice(from, to));
    pos = to;
  }
  return result + content.slice(pos);
}

// Same length, same line breaks, no content. Keeping the length is what
// lets evidence keep pointing at the right column.
function blankRun(run) {
  return run.indexOf('\n') === -1 ? ' '.repeat(run.length) : run.replace(/[^\n]/g, ' ');
}

// Blank out TypeScript syntax the compiler erases, preserving line and
// column offsets the same way blankComments does, so evidence still points
// at the right place. See ERASED_SYNTAX in categories.js for why this is
// syntax-scoped rather than a file skip.
function blankErasedSyntax(code, relPath) {
  const isDeclaration = DECLARATION_FILE_PATTERN.test(relPath);
  let out = code;
  for (const rule of ERASED_SYNTAX) {
    if (rule.declarationFileOnly && !isDeclaration) continue;
    out = out.replace(rule.pattern, (m) => m.replace(/[^\n]/g, ' '));
  }
  return out;
}

// A category pattern is either a RegExp or { match, context }. The second
// form counts only when the line also matches `context`, which is how a
// credential path being opened is separated from one being talked about.
// See sensitiveTargets in categories.js.
// Strips what a source file glues onto a URL literal and rejects a match
// whose host is not one. See ENDPOINT_HOST in categories.js.
function normalizeEndpoint(raw) {
  const url = raw.replace(ENDPOINT_TRAILING_JUNK, '');
  return ENDPOINT_HOST.test(url) ? url : null;
}

function matchRule(rule, text) {
  if (rule instanceof RegExp) return rule.exec(text);
  // Cheap discriminator first. The context regex is an alternation over
  // every filesystem call and was 12% of total scan time when it ran on
  // every line; `.npmrc` and its siblings almost never match, so running
  // them first skips it for practically every line in the corpus.
  const hit = rule.match.exec(text);
  if (!hit) return null;
  return rule.context && !rule.context.test(text) ? null : hit;
}

function ruleSource(rule) {
  return rule instanceof RegExp ? String(rule) : String(rule.match);
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
  // "Nothing was read" and "nothing was found" produce the same empty
  // manifest, and only one of them means the package is inert.
  caps.noReadableSource = { present: false };
  return caps;
}

const SNIPPET_MAX = 200;

// Evidence entries kept per capability category. Once a category is present
// and has this many, another match teaches nothing.
const MAX_EVIDENCE_PER_CATEGORY = 5;

// Distinct literal endpoints and env var names kept per package.
const MAX_ENDPOINTS = 20;
const MAX_ENV_VARS = 40;

// Show the text around the match, not the head of the line. A minified
// bundle is one enormous line, so the first 200 characters of it routinely
// contain nothing to do with what matched: yarn's lib/cli.js reported
// `process.binding(` with a snippet of an unrelated inline-import comment
// from far earlier in the same line. Blanking preserves offsets precisely so
// that an index into the scanned text still addresses the original line.
function excerpt(line, matchIndex) {
  const lead = line.length - line.trimStart().length;
  const trimmed = line.trim();
  if (matchIndex < 0 || trimmed.length <= SNIPPET_MAX) return trimmed.slice(0, SNIPPET_MAX);
  const at = Math.max(0, matchIndex - lead);
  let end = Math.min(trimmed.length, Math.max(0, at - 60) + SNIPPET_MAX);
  const start = Math.max(0, end - SNIPPET_MAX);
  return (start > 0 ? '...' : '') + trimmed.slice(start, end) + (end < trimmed.length ? '...' : '');
}

// `pattern` records which rule matched. Without it a reviewer asking "why
// was this flagged" has to re-derive the answer by eye, and attributing a
// false positive to a specific rule across a large corpus is guesswork.
function addEvidence(list, file, lineNo, line, pattern, max = MAX_EVIDENCE_PER_CATEGORY, matchIndex = -1) {
  if (list.length >= max) return;
  const entry = { file, line: lineNo, snippet: excerpt(line, matchIndex) };
  if (pattern) entry.pattern = String(pattern);
  list.push(entry);
}

function scanFileContent(relPath, content, caps) {
  const longLines = [];
  const codeOnly = blankErasedSyntax(blankComments(content), relPath);
  // Blanking preserves length and line breaks, so both strings share their
  // line boundaries. Walking those boundaries instead of splitting both
  // strings avoids allocating two arrays of every line in the file, and the
  // original line is sliced only when there is evidence to record.
  let lineCount = 0;
  // A declaration file has no executable code to hide, so a long type union
  // is not reduced coverage; graphql's index.d.ts carries 1,722-character
  // lines and made a routine upgrade fail the gate. Capability matching
  // still runs on it, only the long-line signal is suppressed.
  const isGenerated = looksLikeBuildArtifact(relPath) || DECLARATION_FILE_PATTERN.test(relPath);

  // Categories still worth matching in this file. A category that is present
  // with a full evidence quota cannot learn anything from another match, and
  // on a large bundle that is true within the first few lines.
  const active = CATEGORIES.filter(
    (cat) => !(caps[cat.key].present && caps[cat.key].evidence.length >= MAX_EVIDENCE_PER_CATEGORY)
  );

  for (let lineStart = 0; lineStart <= codeOnly.length; ) {
    let lineEnd = codeOnly.indexOf('\n', lineStart);
    if (lineEnd === -1) lineEnd = codeOnly.length;
    const codeLine = codeOnly.slice(lineStart, lineEnd);
    const from = lineStart;
    const to = lineEnd;
    lineStart = lineEnd + 1;
    const lineNo = ++lineCount;

    // Measured on the comment-blanked line with whitespace trimmed off.
    // Blanking preserves length so columns stay accurate, which means a
    // 592-character JSDoc line becomes 592 spaces and used to count as a
    // long line: documentation was being reported as obfuscation. Trimming
    // collapses a blanked comment to nothing while leaving real minified
    // code untouched.
    const codeLength = codeLine.trim().length;
    if (!isGenerated && codeLength > LONG_LINE_THRESHOLD && !GENERATED_LONG_LINE.some((re) => re.test(codeLine))) {
      longLines.push({ lineNo, codeLength });
    }

    for (let ci = 0; ci < active.length; ci++) {
      const cat = active[ci];
      const cap = caps[cat.key];
      for (const rule of cat.patterns) {
        const hit = matchRule(rule, codeLine);
        if (hit) {
          cap.present = true;
          addEvidence(cap.evidence, relPath, lineNo, content.slice(from, to), ruleSource(rule), MAX_EVIDENCE_PER_CATEGORY, hit.index);
          if (cap.evidence.length >= MAX_EVIDENCE_PER_CATEGORY) {
            active.splice(ci, 1);
            ci--;
          }
          break;
        }
      }
    }

    let m;
    if (caps.network.endpoints.length < MAX_ENDPOINTS) {
    URL_PATTERN.lastIndex = 0;
    while ((m = URL_PATTERN.exec(codeLine)) !== null) {
      const url = normalizeEndpoint(m[0]);
      if (url && caps.network.endpoints.length < MAX_ENDPOINTS && !caps.network.endpoints.includes(url)) {
        caps.network.endpoints.push(url);
      }
    }
    }
    if (caps.env.vars.length < MAX_ENV_VARS) {
    ENV_VAR_PATTERN.lastIndex = 0;
    while ((m = ENV_VAR_PATTERN.exec(codeLine)) !== null) {
      const name = m[1] || m[2];
      if (name && caps.env.vars.length < MAX_ENV_VARS && !caps.env.vars.includes(name)) {
        caps.env.vars.push(name);
      }
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
    const avgLineLength = codeOnly.length / Math.max(1, lineCount);
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

// A lifecycle script command runs at install time but is not a file, so the
// directory walk never sees it. See INSTALL_COMMAND_RULES in categories.js.
function scanScriptCommand(scriptKey, command, caps) {
  const where = `package.json#scripts.${scriptKey}`;
  for (const cat of CATEGORIES) {
    for (const rule of cat.patterns) {
      const hit = matchRule(rule, command);
      if (hit) {
        caps[cat.key].present = true;
        addEvidence(caps[cat.key].evidence, where, 1, command, ruleSource(rule), MAX_EVIDENCE_PER_CATEGORY, hit.index);
        break;
      }
    }
  }
  for (const rule of INSTALL_COMMAND_RULES) {
    const hit = rule.pattern.exec(command);
    if (hit) {
      caps[rule.key].present = true;
      addEvidence(caps[rule.key].evidence, where, 1, command, rule.pattern, 5, hit.index);
    }
  }
  let m;
  URL_PATTERN.lastIndex = 0;
  while ((m = URL_PATTERN.exec(command)) !== null) {
    const url = normalizeEndpoint(m[0]);
    if (url && caps.network.endpoints.length < 20 && !caps.network.endpoints.includes(url)) {
      caps.network.endpoints.push(url);
    }
  }
  ENV_VAR_PATTERN.lastIndex = 0;
  while ((m = ENV_VAR_PATTERN.exec(command)) !== null) {
    const name = m[1] || m[2];
    if (name && caps.env.vars.length < MAX_ENV_VARS && !caps.env.vars.includes(name)) caps.env.vars.push(name);
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
  // Deliberately scores nothing. An empty package is usually a stub or a
  // placeholder, and 14% of a random registry sample reads that way, so
  // adding score here would move the ranking without adding information.
  // The flag is the signal, and it gates a diff through lostVisibility.
  if (caps.noReadableSource.present) {
    flags.push(
      'MEDIUM: no source file was read for this package, so an empty capability set here means ' +
        'nothing was scanned rather than nothing was found.'
    );
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
      const command = pkgJson.scripts[key];
      if (typeof command !== 'string' || !command) continue;
      caps.lifecycleScripts.present = true;
      caps.lifecycleScripts.scripts[key] = command;
      // Recorded either way; a reviewer should still see the command. It
      // just isn't code running at install time. See INERT_INSTALL_COMMAND.
      if (INERT_INSTALL_COMMAND.test(command)) continue;
      if (INSTALL_TRIGGERING_SCRIPT_KEYS.includes(key)) {
        caps.lifecycleScripts.installTriggering = true;
      }
      scanScriptCommand(key, command, caps);
    }
  }

  const files = [];
  walk(dir, files);
  for (const target of binTargets(dir, pkgJson)) {
    if (!files.includes(target)) files.push(target);
  }
  caps.noReadableSource.present = files.length === 0;
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

module.exports = { scanPackageDir, walk, binTargets, blankComments, blankErasedSyntax, excerpt, looksLikeBuildArtifact };
