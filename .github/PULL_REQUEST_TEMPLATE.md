## What this changes

<!-- One or two sentences. -->

## Rule changes

Delete this section if no detection rule changed. Otherwise, from
ARCHITECTURE.md:

- [ ] `npm test` passes, with a regression test for the case that motivated it
- [ ] `examples/run-demo.sh` still fails the gate
- [ ] Measured against real packages, not only fixtures: scanned a corpus with
      and without the change and diffed the manifests
- [ ] Ordinary upgrades still pass

Numbers, if you have them:

| | before | after |
|---|---|---|
| packages gaining the capability | | |
| packages losing it | | |
| risk flags changed | | |

Changing a rule changes the rules fingerprint, so every committed baseline
starts meaning something slightly different. That is expected; note it here
so it lands in the changelog.
