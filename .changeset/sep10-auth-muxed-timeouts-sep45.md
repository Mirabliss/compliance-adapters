---
'sep10-auth': minor
---

- `generateChallenge` accepts muxed (`M...`) client accounts and throws `MemoWithMuxedAccountError` when a memo is combined with one. `verifyChallenge` returns `account`, `baseAccount` and (for muxed accounts) `muxedId` in `VerifyResult`.
- `generateChallenge` has a new `timeoutSec` option (default `900`); values `<= 0`, non-finite or `> 3600` throw `InvalidTimeoutError`. `timeoutSeconds` is kept as a deprecated alias. The default window changes from 300 to 900 seconds.
- `verifyChallenge` has a new `clockSkewToleranceSec` option (default `0`) that widens both timebounds symmetrically.
- A SEP-45 prototype (`generateContractChallenge` / `verifyContractChallenge`) for Soroban contract accounts is available from `sep10-auth/dist/sep45`; see `docs/sep45-design.md`.
