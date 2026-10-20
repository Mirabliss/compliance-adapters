---
'sanctions-oracle': minor
---

Add `CircuitBreakerSanctionsProvider` (with `provider_circuit_state` metric), a pluggable `Signer` interface for KMS/HSM keys, optional fee-bump transactions via `feeSource`, and a `maxDurationMs` / `--max-duration` run deadline (exit code 3).
