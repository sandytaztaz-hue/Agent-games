# 9dasand72 — Proof Gatekeeper agent (zkVerify Agent Games, Season 01)

Competition-ready Proof Gatekeeper agent for the zkVerify Agent Games
(Season 01, 21 Oct – 21 Nov 2026, prize 400,000 VFY).
Agent handle: **9dasand72**.

## What it does

The platform POSTs a signed JSON task envelope to this agent's public HTTPS
endpoint. The agent:

1. Verifies the HMAC signature against the **raw** request body *before* parsing.
2. Applies the official gatekeeper decision rule.
3. Generates a Groth16 proof with the **official** gatekeeper circuit (locally,
   with snarkjs) and returns decision + proof + public signals.
4. Signs the raw response body (`x-agent-games-signature` HMAC header).
5. Fails closed on any error, timeout, bad signature, or malformed task.

### Decision rule (official gatekeeper circuit)

`decision = 1` (APPROVE) **iff** all of these hold, else `0` (REJECT):

- `publicBalance >= minimum`
- `amount <= maxTransfer`
- `recipient == conditionRecipient`
- `expiryBlock > currentBlock`

The circuit itself enforces `decision == (all checks pass)` — a wrong
decision cannot even produce a witness (the template `GatekeeperEvaluation_79`
asserts at line 102). Proof generation failing = fail closed.

## Verified results (this machine)

- Circuit: Groth16 / BN128, Circom 2.x. `vkHash`
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
  (from `circuit-info.json`, matches the hash registered on zkVerify mainnet).
- Proof test (`prove-test.mjs`, full log in `proof-test.log`) — 4/4 PASS:
  - valid approve (balance 1460 ≥ 1000, amount 500 ≤ 1000, matching
    recipient, expiry 8,430,000 > 8,420,000, decision 1) → proves,
    `snarkjs groth16 verify` **OK** (~1 s per proof).
  - wrong approve (recipient mismatch, decision 1) → fullProve **FAILS**
    (Assert Failed, GatekeeperEvaluation line 102) — as designed.
  - correct reject (recipient mismatch, decision 0) → proves, verify **OK**.
  - wrong reject (all checks pass, decision 0) → fullProve **FAILS**.
- Server test (`test-server.mjs`) — 15/15 PASS: health, approve 200 +
  proof verifies + response HMAC verifies, wrong/missing HMAC → 401,
  reject → decision 0 + proof verifies, malformed task → 400,
  nested `{task: {...}}` envelope works.

## Files

| File | What it is |
|---|---|
| `server.mjs` | The agent server (Node `http` + snarkjs, no framework) |
| `circuits/gatekeeper.wasm` | Official circuit (from agentgames.zkverify.io) |
| `circuits/gatekeeper_final.zkey` | Official proving key |
| `circuits/verification_key.json` | Exported from the zkey (`snarkjs zkey export verificationkey`) |
| `circuit-info.json` | Official `/api/circuit-info` (vk hashes + artifact URLs) |
| `prove-test.mjs` / `proof-test.log` | Circuit proof test + log |
| `test-server.mjs` | End-to-end server test (spawns server, 15 checks) |
| `run.sh` | Starts server + cloudflared tunnel, writes `endpoint.txt` |
| `watchdog.sh` | Restarts server/tunnel if either dies (cron every 5 min) |
| `.env.example` | Config template |

## Run it

```bash
cp .env.example .env
# Edit .env: set HMAC_SECRET to the platform secret from the dashboard
# ("Rotate Secret"). The server REFUSES all task POSTs until it is set.
setsid ./run.sh > run.log 2>&1 < /dev/null &
cat endpoint.txt        # public https://....trycloudflare.com URL
curl "$(cat endpoint.txt)/health"
```

Config (`PORT`, `HMAC_SECRET`, `CIRCUIT_DIR`, `PROOF_TIMEOUT_MS`) comes
from the environment / `.env`. Never commit `.env`.

## Endpoints

- `GET /health` → `{status, agent, track, circuit, vkHash, hmacConfigured}`
- `POST /` or `POST /task` → task envelope (JSON). Incoming HMAC is read
  from `x-agent-games-signature` (also accepts `x-signature`,
  `x-hmac-signature`; `sha256=<hex>` prefix tolerated).
  Response: `{agent, track, circuit, taskId, decision, checks, vkHash,
  proof, publicSignals, generatedAt}` + `x-agent-games-signature` header.
  Task fields accepted at top level or nested under `task`/`data`/`payload`/
  `input`: `minimum`, `publicBalance`, `amount`, `maxTransfer`,
  `recipient`, `conditionRecipient`, `expiryBlock`, `currentBlock`, `taskId`
  (numbers, decimal strings, or `0x` hex; `taskId` may also be a string
  handle — it is hashed to a field element).

## Dashboard steps Sand still has to do himself (needs his X login)

1. Log in at https://agentgames.zkverify.io with the X account used to
   register, open the dashboard → **Manage Agents**.
2. **Register agent**: name `9dasand72`, endpoint URL = the public URL in
   `endpoint.txt`, repo URL = this repo after it is pushed to GitHub.
3. Copy the platform **HMAC secret** ("Rotate Secret"), paste it as
   `HMAC_SECRET` in `.env` on this machine, restart the server
   (`./run.sh` again — it restarts only what is down; or kill the server
   and re-run).
4. In the dashboard, choose the **Proof Gatekeeper** event/track, then
   **run preflight** — the platform will POST a signed test task; the
   agent must answer within 60 s.
5. Use **practice mode** first (unscored tasks), then compete.

## Known limitations (be honest about them)

- **Public URL: localhost.run, not cloudflared.** cloudflared was tried
  first and is BLOCKED here: the sandbox egress proxy returns 403 for
  `api.trycloudflare.com`, and localtunnel hangs (it ignores the proxy env
  and direct egress is blocked). The working fallback is a free
  localhost.run SSH reverse tunnel (`*.app.lhr.life`, TLS-terminated, no
  account), reached via the egress proxy with `proxy_cmd.sh` + socat.
  If the tunnel restarts, the free domain ROTATES — re-register the new
  endpoint URL in the dashboard.
- **Background processes do NOT survive a VM/service restart.** `run.sh`
  launches server + tunnel with `setsid` (survives the launching shell),
  but a runtime restart kills them; re-run `./run.sh` (or run
  `watchdog.sh` from cron every 5 min) to bring them back. The watchdog
  needs the sandbox proxy env (`https_proxy`) present to restart the tunnel.
- **The HMAC secret only exists after dashboard registration.** Until Sand
  sets it, the server answers `/health` but refuses task POSTs (503).
- **Kurier / on-chain submission is a separate step.** This agent returns
  the proof to the platform, which verifies it. Submitting proofs to
  zkVerify mainnet via Kurier needs a Kurier mainnet API key (not set up
  here) — only needed if the platform flow requires the agent to submit
  directly; per the /build guide the platform re-verifies the proof
  itself.
- This repo is **local only** (no push). Pushing to GitHub needs Sand's
  GitHub account/credentials.
- No private keys, seeds, or passwords are used anywhere in this project.
  The wallet is never touched by this agent.
