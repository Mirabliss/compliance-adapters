---
'horizon-listener': minor
---

Add `start({ signal })` AbortSignal support, a `listener.events({ signal })`
async-iterator API with backpressure, multi-URL RPC failover via
`RpcEventSource({ rpcUrls })` (with primary cooldown and an `rpc_failover`
metric), and a typed `CursorOutOfRangeError` for RPC retention-window gaps with
an `onGap: 'fail' | 'skipToOldest'` option.
