# CheckV2

`orchestrator.ts` exports `runScannerContainer(job)` and `SCANNER_VERSION`, so the worker can switch its orchestrator import when it adopts `CheckV2Result`.

Pipeline:

1. A trusted Railway sandbox fetches the exact commit without running repository code.
2. Trusted `ripgrep` and Semgrep produce compact candidate anchors across the existing scanner's suspicious-behavior taxonomy: input capture, credentials, telemetry, system access, network/process/filesystem activity, dynamic code, supply-chain abuse, persistence, obfuscation, destructive commands, CI, and major security sinks.
3. An investigator Pi session explores the checkout using only `read`, `grep`, `find`, and `ls`, then returns cited candidate findings.
4. A fresh verifier session independently reopens those paths and returns the final findings.

The V2 result intentionally has only `commitSha`, static `candidates`, the investigator draft, verifier `findings`, and a summary. Agent citations are checked against the checkout before a report is retained. There are no application-level scan or agent time limits in this implementation.
