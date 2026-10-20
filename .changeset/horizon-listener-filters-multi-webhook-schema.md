---
"horizon-listener": minor
---

- `RpcEventSource`: new `topics` (topic filters with `*` wildcards) and `eventType` (`contract` | `system` | `diagnostic` | `all`, default `contract`) options, validated at construction and passed through to `getEvents`.
- New `MultiWebhookSender` fans events out to multiple targets with independent retry state, per-target DLQs, and required/optional semantics.
- Webhook deliveries now include an `X-Compliance-Schema-Version: 1` header and a `schemaVersion` body field.
