# Dependency capability review

1 installation(s) scanned. 1 entry/entries to review.

**The capability check would fail.**

## write\-file\-atomic: 2\.4\.3 → 3\.0\.3

Review ID: `240263f7fc7fc91f483e707b4159b6a9`

Installation: write\-file\-atomic. Match: install\-path.

**Explicit review required.**

Blocking reasons:

- "Filesystem write" was not present in 2\.4\.3 but appears in 3\.0\.3\.
- "Filesystem removal" was not present in 2\.4\.3 but appears in 3\.0\.3\.

Content SHA-256: `fdee769180ada4b9f14120f54f75189e731a4a86c4aa8addc7f0ebec7d3fa36f`.

- **capability\-added:** "Filesystem write" was not present in 2\.4\.3 but appears in 3\.0\.3\.
- **capability\-added:** "Filesystem removal" was not present in 2\.4\.3 but appears in 3\.0\.3\.

Coverage: 1 source file(s) read; 0 skipped; 0 I/O error(s).

Input: verified npm tarball. Integrity: sha512\-AvHcyZ5JnSfq3ioSyjrBkH9yW4m7Ayk8/9My/DD9onKeu/94fwrMocemO2QAJFAlnnDN\+ZDS\+ZjAR5ua1/PV/Q==.

File correlation:

Network and credential indicators occur together in 0 analyzed source file\(s\)\.
File co\-occurrence does not establish execution order or data transfer\. Missing matches do not prove absence of those behaviors\.

Source evidence:

- index\.js:113 (filesystemWrite): await promisify\(fs\.write\)\(fd, data, 0, data\.length, 0\)
- index\.js:115 (filesystemWrite): await promisify\(fs\.write\)\(fd, String\(data\), 0, String\(options\.encoding \|\| 'utf8'\)\)
- index\.js:141 (filesystemWrite): await promisify\(fs\.rename\)\(tmpfile, truename\)
- index\.js:213 (filesystemWrite): fs\.writeSync\(fd, data, 0, data\.length, 0\)
- index\.js:215 (filesystemWrite): fs\.writeSync\(fd, String\(data\), 0, String\(options\.encoding \|\| 'utf8'\)\)
- index\.js:43 (filesystemRemove): fs\.unlinkSync\(typeof tmpfile === 'function' ? tmpfile\(\) : tmpfile\)
- index\.js:150 (filesystemRemove): await promisify\(fs\.unlink\)\(tmpfile\)\.catch\(\(\) =&gt; \{\}\)

Selective approval binds one installation to its version and installed file content. It does not certify safety or execute scripts.
