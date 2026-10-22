---
'horizon-listener': minor
---

- `HorizonListener`: new `concurrency` and `orderingKey` options for bounded parallel `onEvent` processing with per-contract ordering; the cursor only advances after a page is fully processed.
- `HttpWebhookSender`: new `headers` option (reserved headers cannot be overridden).
- `HttpWebhookSender`: error response bodies are capped at 2 KB, stripped of control characters and marked when truncated.
- `HttpWebhookSender`: new `tls` (mTLS via undici `Agent`) and `dispatcher` options.
