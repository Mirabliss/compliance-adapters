---
'sanctions-oracle': minor
---

- CLI: `--json` prints only the JSON `SyncResult` on stdout and routes logs to stderr.
- New `createJsonlAuditLogger(path, { fsync })` append-only JSONL audit sink, plus CLI `--audit-log <path>`.
- New `FileCheckpointStore` with atomic writes and recovery from corrupt/truncated checkpoint files, plus CLI `--checkpoint <path>`.
- New example Chainalysis sanctions screening provider in `examples/providers/chainalysis.ts`.
