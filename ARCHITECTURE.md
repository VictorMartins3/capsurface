# Architecture

Five modules, one direction of data flow, no framework. The whole thing is
readable in one sitting, which is deliberate: this is a security tool, so
being auditable by the person adopting it is a feature.

```
bin/capsurface.js      CLI only: arguments, output, exit codes
      |
      v
lib/discovery.js       which directories are packages, and the symlink boundary
      |
      v
lib/scanner.js         one package directory -> one capability manifest
      |                (uses lib/categories.js for the rules)
      v
lib/diff.js            baseline manifest(s) vs current -> escalation report
```

## Where to change what

| You want to | Edit |
|---|---|
| Add or fix a detection rule | `lib/categories.js` |
| Change how source is read or capabilities extracted | `lib/scanner.js` |
| Change what fails the build vs. what is only reported | `lib/diff.js` |
| Change how packages are found on disk | `lib/discovery.js` |
| Change CLI flags, output, exit codes | `bin/capsurface.js` |

`lib/rules-version.js` hashes everything in `categories.js` that affects a
manifest. Touching a rule changes that hash, and `check` then warns that
existing baselines were written by different rules. That is intentional:
edit a rule and every committed baseline now means something slightly
different, which a security gate must not hide.

## The two decisions that shape everything

**Detection is separate from gating.** `scanner.js` records what a package
can do. `diff.js` decides whether a change in that is worth failing a build
over. They are deliberately not the same judgement: reading an env var is
worth recording and not worth blocking, so `env` carries
`gatesOnAppear: false`. Keep new rules on this split. Record generously,
gate narrowly.

**Rules key on acquisition, not on a name.** `exec` matches
`require('child_process')`, not `exec(`, because method names collide with
unrelated APIs. `RegExp.prototype.exec`, lru-cache's `fetch(k, opts)`,
rxjs's `connectable.connect()`, puppeteer's `$eval` and `redis.eval()` all
produced false positives when a rule matched a bare call, and
`endsWith('.node')` did the same for native code. If a new rule must match a
call site, expect it to be wrong on a corpus and check before shipping it.

## Rule forms in `categories.js`

A category pattern is either a plain `RegExp` or `{ match, context }`. The
second counts only when `context` also matches, within a window around the
match rather than anywhere on the line: a minified bundle is one enormous
line, so a line-scoped context is satisfied by anything in the file. That is
what separates `path.join(dir, '.npmrc')` from a help string mentioning
`~/.ssh/config`. Put the cheap discriminator in `match`; it runs first.

Three things are matched outside the category loop:

- `ERASED_SYNTAX` blanks TypeScript the compiler removes, `import type` and
  every import in a `.d.ts`, before any rule sees it. The file is still
  scanned, because `require('./x.d.ts')` executes.
- `INSTALL_COMMAND_RULES` matches lifecycle script commands, which are shell
  lines rather than JavaScript. Commands are also run through the ordinary
  JavaScript rules, which is what reaches an inline `node -e` payload. Only
  install-triggering scripts contribute capabilities; `prepare` does not run
  for a registry install.
- `GENERATED_LONG_LINE` and `BUILD_ARTIFACT_PATH` decide what the
  obfuscation signal ignores. Both describe machine-generated output, and
  neither suppresses capability matching.

## Manifest shape

```jsonc
{
  "schemaVersion": 3,
  "rulesVersion": "ce7db165b1f1",  // hash of the rules that produced this
  "name": "pkg", "version": "1.2.3",
  "sourceFilesScanned": 12, "sourceFilesSkipped": 0,
  "capabilities": {
    "filesystem":  { "present": true, "evidence": [ /* file, line, snippet, pattern */ ] },
    "network":     { "present": true, "evidence": [], "endpoints": [] },
    "env":         { "present": true, "evidence": [], "vars": [] },
    "lifecycleScripts": { "present": true, "installTriggering": true, "scripts": {} },
    "obfuscationSignal": { "present": false, "evidence": [] },
    "skippedLargeFiles": { "present": false, "count": 0, "files": [] },
    "noReadableSource":  { "present": false }  // nothing was read, ≠ nothing found
    // plus exec, dynamicEval, nativeFfi, sensitiveTargets
  },
  "riskScore": 14,
  "riskFlags": ["CRITICAL: ..."]
}
```

Every evidence entry carries the `pattern` that matched it. That is what
makes it possible to ask "which rule produced this finding" across
thousands of packages, which is how the rule errors listed in
`CHANGELOG.md` were found.

## Testing a rule change

A rule change is not done until it has been measured against real packages,
not just fixtures. The invariants:

1. `npm test` passes.
2. `./examples/run-demo.sh` still fails the gate.
3. Routine dependency upgrades still pass. A gate that fires on ordinary
   upgrades gets switched off, so this matters as much as detection. The
   standing measurement is 82 popular packages diffed across two years:
   3 escalations, each explainable (see CHANGELOG.md). A change that raises
   that number needs a reason.
4. Scanning real packages produces no new CRITICAL on benign ones. Measure
   it: scan a corpus with and without the change and diff the manifests.
   Every rule change in CHANGELOG.md carries the number that produced.

`CHANGELOG.md` records the corpora these were measured against and the
numbers each change produced.
