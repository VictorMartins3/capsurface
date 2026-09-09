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

**Rules key on imports, not call sites.** `exec` matches
`require('child_process')`, not `exec(`, because method names collide with
unrelated APIs. `RegExp.prototype.exec`, lru-cache's `fetch(k, opts)` and
rxjs's `connectable.connect()` all produced false positives when a rule
matched a bare call. If a new rule must match a call site, expect it to be
wrong on a corpus and check before shipping it.

## Manifest shape

```jsonc
{
  "schemaVersion": 3,
  "rulesVersion": "89b2f56e8fbf",  // hash of the rules that produced this
  "name": "pkg", "version": "1.2.3",
  "sourceFilesScanned": 12, "sourceFilesSkipped": 0,
  "capabilities": {
    "filesystem":  { "present": true, "evidence": [ /* file, line, snippet, pattern */ ] },
    "network":     { "present": true, "evidence": [], "endpoints": [] },
    "env":         { "present": true, "evidence": [], "vars": [] },
    "lifecycleScripts": { "present": true, "installTriggering": true, "scripts": {} },
    "obfuscationSignal": { "present": false, "evidence": [] },
    "skippedLargeFiles": { "present": false, "count": 0, "files": [] }
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
3. A routine dependency upgrade still produces zero escalations. A gate
   that fires on ordinary upgrades gets switched off, so this matters as
   much as detection.
4. Scanning real trees produces no new CRITICAL on benign packages.

`CHANGELOG.md` records the corpora these were measured against and the
numbers each change produced.
