---
'@compliance-adapters/backoff': patch
---

Add AbortSignal-aware `sleep()` helper that rejects with AbortError and clears its timer.
