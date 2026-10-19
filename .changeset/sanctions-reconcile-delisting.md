---
'sanctions-oracle': minor
---

Add opt-in delisting. `SyncOptions.reconcile` re-checks `currentDenylist`
entries and removes those the provider has cleared through the writer's new
`removeFromDenylist` / `removeFromDenylistWithSource` (implemented by
`createRpcDenylistWriter` via `remove_from_denylist`). `SyncResult` gains
`removed`, `plannedRemovals` (shown in dry-run) and `failedRemovals` in
reconcile mode, `AuditLogEntry` gains `action: 'remove'`, and the CLI gains
`--reconcile` and `--denylist-snapshot <path>`.
