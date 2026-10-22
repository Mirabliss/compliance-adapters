# sep10-browser-login

> A runnable browser example that authenticates a Stellar address using the
> [SEP-10](https://stellar.org/protocol/sep-10) web-auth protocol and the
> [Freighter](https://www.freighter.app/) browser wallet.

**Stack:** Vite · Vanilla TypeScript · `@stellar/freighter-api` · `@stellar/stellar-sdk`

---

## What this example shows

The existing examples in this repo cover only the _server_ side of SEP-10 — how
to generate and verify challenges. This example fills in the _client_ side:

| Step | What happens |
|------|-------------|
| 1 | User clicks **Connect Freighter** — the page calls `requestAccess()` and stores the public key. |
| 2 | User clicks **Login with SEP-10** — the page calls `GET /auth?account=<G…>` and receives an unsigned XDR challenge transaction. |
| 3 | The challenge XDR is passed to Freighter's `signTransaction()`, which pops the browser extension signing dialog. |
| 4 | The signed XDR is posted to `POST /auth`; the server verifies it and returns a JWT. |
| 5 | The JWT is stored in `sessionStorage` and displayed on the page. |

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **Node 20+** | Run `node --version` to check. |
| **Freighter extension** | Install from [freighter.app](https://www.freighter.app/). Switch it to **Testnet** in Settings → Network. |
| **Example API server** | The Vite dev server proxies `/auth` to the `full-stack-demo` server (default: `http://localhost:3001`). |

---

## Quick start

### 1 · Start the API server

The Vite dev server proxies `/auth` to the `full-stack-demo` server. Start it
first:

```bash
# From the repo root
npm install
npm run build

# Start the example server (needs a testnet keypair)
cd examples/full-stack-demo
# Generate a testnet keypair if you don't have one:
#   node -e "const { Keypair } = require('@stellar/stellar-sdk'); const kp = Keypair.random(); console.log('SECRET:', kp.secret()); console.log('PUBLIC:', kp.publicKey());"
SERVER_SECRET=S... node server.js
```

The server starts on **`http://localhost:3001`** by default.

### 2 · Configure the browser example (optional)

```bash
cd examples/sep10-browser-login
cp .env.example .env
```

Edit `.env` if your server runs on a different port:

```dotenv
VITE_SERVER_URL=http://localhost:3001
VITE_NETWORK_PASSPHRASE=Test SDF Network ; September 2015
```

> The defaults work out of the box with `full-stack-demo` and Stellar testnet.
> You do not need to edit `.env` for a local run.

### 3 · Install and run the dev server

```bash
# From the repo root
npm install --workspace=sep10-browser-login

# Start the Vite dev server
npm run dev --workspace=sep10-browser-login
```

Open **[http://localhost:5173](http://localhost:5173)** in the browser that has
Freighter installed.

---

## Walkthrough

### Step 1 — Connect Freighter

Click **Connect Freighter**.

Freighter pops a permission dialog asking whether to allow this origin
(`localhost:5173`) to read your public key. Click **Approve**.

The page reads your Stellar address and shows it next to the **Login** button.

```
┌──────────────────────────────────────────────┐
│  Connected as GABC…XYZ. Click Login to auth. │
│                                              │
│  [ Login as GABC…XYZ ]                       │
└──────────────────────────────────────────────┘
```

> **No network request is made at this stage.** The address is obtained
> entirely from the Freighter extension.

### Step 2 — Fetch the challenge

Click **Login with SEP-10**.

The page calls:

```
GET /auth?account=GABC…XYZ
```

The server responds with an unsigned Stellar transaction (the SEP-10 challenge):

```json
{
  "transaction": "AAAAAgAAAAB...<base64 XDR>",
  "network_passphrase": "Test SDF Network ; September 2015"
}
```

The debug log shows:

```
[2026-10-20 16:23:10.123] Fetching challenge from server…
```

### Step 3 — Sign with Freighter

The XDR is passed to Freighter's `signTransaction()` API. Freighter opens its
signing dialog — it decodes and shows you exactly which operations are in the
transaction (a `manageData` operation with `home_domain auth` as the key).

Click **Approve** in the Freighter popup.

```
┌─ Freighter ──────────────────────────────────┐
│  Sign Transaction                            │
│                                              │
│  Network: Stellar Testnet                    │
│  Operations:                                 │
│    manageData  sep10-demo.localhost auth      │
│                                              │
│  [ Approve ]   [ Decline ]                   │
└──────────────────────────────────────────────┘
```

### Step 4 — Submit and receive the token

The signed XDR is posted to `POST /auth`:

```
POST /auth
Content-Type: application/json

{ "transaction": "AAAAAgAAAAB...<signed XDR>" }
```

The server verifies that:

1. The transaction contains a `manageData` operation for the correct home domain.
2. The transaction is signed by the key that matches the `account` query parameter.
3. The challenge has not expired (5-minute window by default).

On success:

```json
{ "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }
```

### Result panel

The page now shows:

```
┌─ Authenticated ✓ ──────────────────────────────────────────┐
│  Stellar address   GABC…XYZ                                │
│  Network           Test SDF Network ; September 2015       │
│  JWT token         eyJhbGciOiJIUzI1NiIs…  (truncated)     │
└────────────────────────────────────────────────────────────┘
```

The token is stored in `sessionStorage` under the key `sep10_token`. You can
read it in DevTools → Application → Session Storage.

Use it as a `Bearer` token on any protected API endpoint:

```bash
curl -H "Authorization: Bearer eyJhbGciOi..." \
     http://localhost:3001/private
```

### Logout

Click **Logout** to remove the token from `sessionStorage` and reset the UI.

> **Server-side revocation:** the `full-stack-demo` server exposes
> `POST /auth/revoke`. Wire it up in `clearSession()` inside `src/sep10.ts` if
> you need tokens to be invalidated on the server before they expire.

---

## Project layout

```
sep10-browser-login/
├── index.html          # Single-page HTML shell
├── vite.config.ts      # Vite config — proxies /auth to the API server
├── tsconfig.json       # Browser-targeted TS config (ESNext + DOM lib)
├── .env.example        # Environment variable template
└── src/
    ├── main.ts         # Entry point — wires DOM events to sep10.ts helpers
    ├── sep10.ts        # Core SEP-10 flow (fetchChallenge · signChallenge · submitChallenge)
    ├── ui.ts           # DOM helpers (step indicators, status banner, log)
    └── style.css       # Dark-mode styles
```

---

## Key APIs

### `src/sep10.ts`

| Export | Description |
|--------|-------------|
| `isFreighterAvailable()` | Returns `true` if the extension is installed. |
| `connectFreighter()` | Requests access and returns the selected public key. |
| `fetchChallenge(account)` | `GET /auth?account=…` → `{ transaction, network_passphrase }` |
| `signChallenge(xdr, account)` | Calls `signTransaction()` via Freighter. |
| `submitChallenge(signedXdr)` | `POST /auth { transaction }` → JWT string. |
| `runSep10Login(onProgress?)` | Runs all four steps in sequence; returns `Sep10Session`. |
| `getStoredToken()` | Returns the JWT from `sessionStorage`, or `null`. |
| `clearSession()` | Removes the JWT from `sessionStorage`. |

### `Sep10Session`

```ts
interface Sep10Session {
  address: string;          // Verified Stellar public key (G…)
  token: string;            // JWT returned by the server
  networkPassphrase: string; // Network the challenge was issued for
}
```

---

## Using the token

Once you have the JWT, include it as a Bearer token in every authenticated
request:

```ts
async function callProtectedEndpoint(token: string): Promise<unknown> {
  const res = await fetch('/private', {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return res.json();
}
```

The token encodes the verified Stellar address as the `sub` (subject) claim.
Decode it on the server with any JWT library — the `full-stack-demo` and
`sep10-auth` package use the same HMAC-SHA256 secret on both ends.

---

## Building for production

```bash
npm run build --workspace=sep10-browser-login
```

The output lands in `examples/sep10-browser-login/dist/`. Serve it with any
static file server. Make sure to configure CORS on your API server so that it
accepts requests from your production origin, **or** configure your reverse
proxy to route `/auth` requests to the API server (same-origin avoids CORS
entirely and is the recommended approach).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| "Freighter extension not found" | Extension not installed / not enabled on `localhost` | Install from [freighter.app](https://www.freighter.app/) |
| Challenge fetch returns 400 | `account` param missing or invalid | Check that Freighter returned a valid `G…` key |
| Freighter signing dialog does not appear | Page is not `https://` or `http://localhost` | Run the dev server on `localhost` |
| `signTransaction` returns an error | Freighter set to wrong network | Switch Freighter to **Testnet** in Settings |
| POST /auth returns 400 "invalid challenge" | Transaction expired or wrong keypair | Click Login again to get a fresh challenge |
| Token not persisting across tabs | `sessionStorage` is tab-isolated by design | Use `localStorage` if cross-tab persistence is needed (security trade-off) |

---

## Related resources

- [SEP-10 spec](https://stellar.org/protocol/sep-10)
- [Freighter API docs](https://docs.freighter.app/docs/freighter-api)
- [`sep10-auth` package](../../sep10-auth/README.md) — server-side challenge generation and verification
- [`examples/full-stack-demo`](../full-stack-demo/README.md) — the API server this example talks to
- [`examples/sep10-sanctions-gate`](../sep10-sanctions-gate) — server-side gated route example
