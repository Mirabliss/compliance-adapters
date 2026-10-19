# SEP-45 design note (prototype)

Status: prototype, in `sep10-auth/src/sep45.ts`. It is not exported from the
package index, so the SEP-10 API is unaffected.

## Why

[SEP-10](https://stellar.org/protocol/sep-10) authenticates classic accounts
(`G...`, and muxed `M...`) with a signed `manage_data` transaction. A Soroban
contract account (`C...`, e.g. a smart wallet) has no ed25519 key and cannot sign
a classic transaction, so compliance flows that gate smart-wallet users cannot
authenticate them with SEP-10.
[SEP-45](https://stellar.org/protocol/sep-45) fixes this by authenticating through
Soroban authorization entries.

| Account type | Standard |
|---|---|
| `G...`, `M...` | SEP-10 |
| `C...` | SEP-45 |

## Flow

1. **Challenge request.** The client sends its contract account (`C...`) to the
   anchor.
2. **`generateContractChallenge`.** The server builds two
   `SorobanAuthorizationEntry` values for the same root invocation,
   `web_auth_verify(args)` on the anchor's web-auth contract (no
   sub-invocations):
   - an entry whose credentials are the **server account**, signed by the
     server keypair (`authorizeEntry`), and
   - an entry whose credentials are the **client contract account**, left
     unsigned.

   `args` is a single `Map<String,String>` with keys `account` (client `C...`),
   `home_domain`, `web_auth_domain`, `web_auth_domain_account` (server `G...`) and
   a random `nonce`. Both entries expire at `validUntilLedger`.
3. **Client signs.** The client signs its entry (its contract's `__check_auth`
   defines what a valid signature is) and returns both entries.
4. **`verifyContractChallenge`.** The server checks that:
   1. there are exactly two entries, each a `web_auth_verify` call on
      `webAuthContractId` with no sub-invocations and identical arguments;
   2. one entry is the server's and the other is a `C...` account equal to the
      `account` argument;
   3. `home_domain` / `web_auth_domain` are in the allowed lists and
      `web_auth_domain_account` is the server account;
   4. neither entry has expired (`currentLedger`, when supplied);
   5. the server entry carries a valid ed25519 signature by the server key over
      the authorization preimage;
   6. the client entry is signed and `verifyClientAuthorization` accepts it.
5. **Result.** `{ valid, address, nonce, homeDomain }`. The caller issues its
   session token and records the `nonce` to prevent replay.

## Differences from SEP-10 in this API

| | SEP-10 | SEP-45 prototype |
|---|---|---|
| Challenge | `manage_data` transaction XDR | list of base64 `SorobanAuthorizationEntry` |
| Sync/async | sync | async (entry signing is async in the SDK) |
| Client signature check | ed25519, done by the SDK | contract `__check_auth`; delegated to `verifyClientAuthorization` |
| Expiry | transaction timebounds | `signatureExpirationLedger` (ledgers, not seconds) |

## Limits of the prototype

- **Client signature validation is delegated.** A contract account's signature
  can only be validated by running its `__check_auth`, normally by simulating
  `web_auth_verify` with the signed entries through Soroban RPC. This package does
  not call RPC, so `verifyClientAuthorization` is required; without a real
  implementation a forged client entry would be accepted.
- Only `SOROBAN_CREDENTIALS_ADDRESS` entries are accepted.
- `client_domain` / `client_domain_account` arguments are not supported.
- Entries are returned as a list of base64 strings rather than a single
  base64-encoded XDR array.
- Replay protection (tracking used `nonce` values) is left to the caller.
