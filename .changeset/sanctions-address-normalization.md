---
'sanctions-oracle': minor
---

Addresses are now normalized (trimmed and uppercased via the new shared
`normalizeStellarAddress`) at every ingestion boundary — sync input and
`currentDenylist`, the CLI, `CsvSanctionsProvider`, `MockSanctionsProvider` and
`RestSanctionsProvider` — so padded or mixed-case spellings of one account map
to a single canonical address for provider lookups, cache keys and denylist
writes.
