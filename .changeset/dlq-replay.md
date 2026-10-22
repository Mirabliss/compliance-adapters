---
"horizon-listener": minor
---

Add `compliance-adapters dlq replay --dlq --webhook [--dry-run] [--limit N]` and `replayDeadLetterQueue()` helper; entries are removed only after successful redelivery.
