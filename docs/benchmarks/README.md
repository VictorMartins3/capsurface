# Deep analysis experiments, September 29, 2026

## Batched JavaScript analysis

`node bench/deep.cjs /path/to/baseline /path/to/package ...` compares a checkout
of the previous engine with the current implementation. Our baseline was
`1b7a9c7d0e3bb0be6090a3a86adc7fe005e92dab`. Both checkouts had Acorn 8.15.0 and
acorn-typescript 1.4.13 available. Inspected programs are never executed.

Median milliseconds from three runs on Apple M5, macOS arm64, Node 26.8.1:

| Input | Files | Previous | Current, empty analysis cache | Current, warm analysis cache |
| --- | ---: | ---: | ---: | ---: |
| Synthetic small sources | 50 | 1325.36 | 61.20 | 1.78 |
| commander | 8 | 269.63 | 96.37 | 47.16 |
| koa | 8 | 236.71 | 67.02 | 33.71 |

The filesystem cache was warm. Current analysis also has additional flow models,
so this measures complete scans with different capabilities. These small samples
do not estimate p95 or peak memory. Both versions reported the same existing
unavailable file in each real package: a declaration parse error in commander,
and an AST resource limit in koa. Failed analyses are retried rather than cached.

[Raw timings, package versions, content digests and coverage](deep-2026-09-29.json).

## Optional Oxc experiment

Install `oxc-parser@0.152.0` in a separate experiment directory, then run:

```sh
node bench/oxc-parity.cjs /path/to/experiment/node_modules/oxc-parser
```

The adapter uses the Rust parser through its Node binding, enables semantic
diagnostics, materializes source locations, and feeds the existing JavaScript
analysis. It is not a Rust implementation of the analysis or an isolated backend.

Nine of ten synthetic cases had identical results, including the tested Unicode,
TypeScript and malformed-source cases. Oxc accepted an explicit resource
management declaration that our ECMAScript 2022 Acorn configuration rejected.
Timing the adapter inside the process does not demonstrate an end-to-end gain
over batched analysis. No Rust backend is enabled or shipped as a dependency.

[Raw parity results and timings](oxc-2026-09-29.json).

A production integration still needs a representative parity corpus, an explicit
syntax contract, isolated worker benchmarks, peak memory measurements and
platform/distribution checks. These measurements do not meet those conditions.
