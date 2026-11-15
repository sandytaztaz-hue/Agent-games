// 9dasand72 — Proof Gatekeeper agent for zkVerify Agent Games (Season 01).
// Plain Node.js http server + snarkjs. No framework, no secrets in code.
//
// Flow per https://agentgames.zkverify.io/build:
//   1. Platform POSTs a signed JSON task envelope to this endpoint.
//   2. We verify the HMAC signature against the RAW body BEFORE parsing.
//   3. We apply the gatekeeper decision rule, generate a Groth16 proof
//      with the official circuit, and return decision + proof + public signals.
//   4. The response body is HMAC-signed (header: x-agent-games-signature).
//   5. Hard deadline 60s, HTTPS only, FAIL CLOSED on any error/uncertainty.
//
// Config (environment):
//   PORT         - local listen port (default 3000)
//   HMAC_SECRET  - platform-generated secret from dashboard "Rotate Secret".
//                  REQUIRED for task POSTs. If unset, task POSTs are refused
//                  with 503 (fail closed); /health still answers.
//   CIRCUIT_DIR  - directory with gatekeeper.wasm / gatekeeper_final.zkey /
//                  verification_key.json (default ./circuits)
//   PROOF_TIMEOUT_MS - max ms for one proof (default 50000)
//
// Decision rule (official gatekeeper circuit):
//   decision = 1 (APPROVE)  IFF  publicBalance >= minimum
//                            AND amount <= maxTransfer
//                            AND recipient == conditionRecipient
//                            AND expiryBlock > currentBlock
//   otherwise decision = 0 (REJECT).
// The circuit itself enforces decision == (all checks pass): a wrong decision
// cannot even produce a witness, so proof generation failing = fail closed.

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = Number(process.env.PORT || 3000);
const HMAC_SECRET = process.env.HMAC_SECRET || "";
// Circuit files live in ./circuits by default. If someone uploads the repo
// flat (e.g. via the GitHub web uploader on a phone, which drops subfolders),
// fall back to the repo root so the agent still runs.
const CIRCUIT_DIR = process.env.CIRCUIT_DIR
  || (fs.existsSync(path.join(__dirname, "circuits", "gatekeeper.wasm"))
    ? path.join(__dirname, "circuits")
    : __dirname);
const PROOF_TIMEOUT_MS = Number(process.env.PROOF_TIMEOUT_MS || 50000);
const MAX_BODY_BYTES = 1_000_000;

// BN128 scalar field prime (snarkjs/bn128).
const PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const WASM_PATH = path.join(CIRCUIT_DIR, "gatekeeper.wasm");
const ZKEY_PATH = path.join(CIRCUIT_DIR, "gatekeeper_final.zkey");
const VKEY_PATH = path.join(CIRCUIT_DIR, "verification_key.json");
const CIRCUIT_INFO_PATH = path.join(__dirname, "circuit-info.json");

const AGENT = "9dasand72";
const TRACK = "proof-gatekeeper";

// ---------------------------------------------------------------------------
// Startup: load circuit info + verification key.
// ---------------------------------------------------------------------------
const circuitInfo = JSON.parse(fs.readFileSync(CIRCUIT_INFO_PATH, "utf8"));
const VK_HASH_HEX = circuitInfo.circuits.gatekeeper.vkHash;
const VK_HASH_FIELD = (BigInt(VK_HASH_HEX) % PRIME).toString();
const VKEY = JSON.parse(fs.readFileSync(VKEY_PATH, "utf8"));

for (const p of [WASM_PATH, ZKEY_PATH]) {
  if (!fs.existsSync(p)) throw new Error(`missing circuit file: ${p}`);
}

console.log(`[${AGENT}] gatekeeper vkHash: ${VK_HASH_HEX}`);
console.log(`[${AGENT}] HMAC secret configured: ${HMAC_SECRET ? "yes" : "NO — task POSTs will be refused (fail closed)"}`);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function hmacHex(secret, data) {
  return crypto.createHmac("sha256", secret).update(data).digest("hex");
}

function verifyHmac(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  let sig = headerValue.trim();
  if (sig.toLowerCase().startsWith("sha256=")) sig = sig.slice(7);
  const expected = hmacHex(secret, rawBody);
  const a = Buffer.from(sig, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function toFieldBigInt(value, name) {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) throw new Error(`${name} must be a non-negative integer`);
    return BigInt(value);
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^[0-9]+$/.test(s)) return BigInt(s);
    throw new Error(`${name} is not a number or hex string: ${s.slice(0, 40)}`);
  }
  throw new Error(`${name} has unsupported type ${typeof value}`);
}

function normalizeAddress(value, name) {
  const n = toFieldBigInt(value, name);
  if (n >= 2n ** 160n) throw new Error(`${name} is not a valid address-sized value`);
  return n;
}

// taskId may be a string handle/UUID: derive a deterministic field element.
function taskIdToField(taskId) {
  if (taskId === undefined || taskId === null || taskId === "") return 0n;
  if (typeof taskId === "number" && Number.isInteger(taskId) && taskId >= 0) return BigInt(taskId);
  if (typeof taskId === "string" && /^[0-9]+$/.test(taskId.trim())) return BigInt(taskId.trim());
  const h = crypto.createHash("sha256").update(String(taskId)).digest();
  return BigInt("0x" + h.toString("hex")) % PRIME;
}

function randomSalt() {
  let s = 0n;
  while (s === 0n) s = BigInt("0x" + crypto.randomBytes(31).toString("hex")) % PRIME;
  return s;
}

const FIELD_ALIASES = {
  minimum: ["minimum", "minBalance", "min_balance", "threshold"],
  publicBalance: ["publicBalance", "balance", "public_balance"],
  amount: ["amount", "transferAmount", "value"],
  maxTransfer: ["maxTransfer", "maxAmount", "max_transfer"],
  recipient: ["recipient", "to", "target", "destination"],
  conditionRecipient: ["conditionRecipient", "expectedRecipient", "condition_recipient", "allowedRecipient"],
  expiryBlock: ["expiryBlock", "expiry", "expiresAtBlock", "expiry_block"],
  currentBlock: ["currentBlock", "blockNumber", "current_block"],
  taskId: ["taskId", "task_id", "id", "taskID"],
};

function pickField(obj, names) {
  for (const n of names) {
    if (obj && obj[n] !== undefined && obj[n] !== null) return obj[n];
  }
  return undefined;
}

function extractTask(body) {
  // Accept top-level fields, or nested under task / data / payload / input.
  const candidates = [body];
  for (const k of ["task", "data", "payload", "input", "gatekeeper", "envelope"]) {
    if (body && typeof body[k] === "object" && body[k] !== null) candidates.push(body[k]);
  }
  let task = null;
  for (const c of candidates) {
    if (pickField(c, FIELD_ALIASES.minimum) !== undefined) { task = c; break; }
  }
  if (!task) task = candidates[0] || {};
  return task;
}

function decide(t) {
  const minimum = toFieldBigInt(pickField(t, FIELD_ALIASES.minimum), "minimum");
  const publicBalance = toFieldBigInt(pickField(t, FIELD_ALIASES.publicBalance), "publicBalance");
  const amount = toFieldBigInt(pickField(t, FIELD_ALIASES.amount), "amount");
  const maxTransfer = toFieldBigInt(pickField(t, FIELD_ALIASES.maxTransfer), "maxTransfer");
  const recipient = normalizeAddress(pickField(t, FIELD_ALIASES.recipient), "recipient");
  const conditionRecipient = normalizeAddress(pickField(t, FIELD_ALIASES.conditionRecipient), "conditionRecipient");
  const expiryBlock = toFieldBigInt(pickField(t, FIELD_ALIASES.expiryBlock), "expiryBlock");
  const currentBlock = toFieldBigInt(pickField(t, FIELD_ALIASES.currentBlock), "currentBlock");
  const taskIdRaw = pickField(t, FIELD_ALIASES.taskId);

  const checks = {
    balanceOk: publicBalance >= minimum,
    amountOk: amount <= maxTransfer,
    recipientOk: recipient === conditionRecipient,
    expiryOk: expiryBlock > currentBlock,
  };
  const decision = Object.values(checks).every(Boolean) ? 1 : 0;

  const input = {
    registeredVkHash: VK_HASH_FIELD,
    proofVkHash: VK_HASH_FIELD,
    minimum: minimum.toString(),
    publicBalance: publicBalance.toString(),
    expiryBlock: expiryBlock.toString(),
    currentBlock: currentBlock.toString(),
    recipient: recipient.toString(),
    conditionRecipient: conditionRecipient.toString(),
    amount: amount.toString(),
    maxTransfer: maxTransfer.toString(),
    decision: String(decision),
    taskId: taskIdToField(taskIdRaw).toString(),
    salt: randomSalt().toString(),
  };
  return { decision, checks, input, taskIdRaw: taskIdRaw === undefined ? null : String(taskIdRaw) };
}

// ---------------------------------------------------------------------------
// Proof generation (serialized: one proof at a time; each is CPU-heavy).
// ---------------------------------------------------------------------------
let proofQueue = Promise.resolve();

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise.finally(() => clearTimeout(timer)), timeout]);
}

function generateProof(input) {
  const job = proofQueue.then(async () => {
    const { proof, publicSignals } = await withTimeout(
      snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH),
      PROOF_TIMEOUT_MS,
      "proof generation"
    );
    const ok = await snarkjs.groth16.verify(VKEY, publicSignals, proof);
    if (!ok) throw new Error("local proof verification failed");
    return { proof, publicSignals };
  });
  // Keep the queue alive even if this job fails.
  proofQueue = job.catch(() => {});
  return job;
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------
function sendJson(res, status, obj, sign = false) {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  const headers = { "content-type": "application/json", "content-length": body.length };
  if (sign && HMAC_SECRET) headers["x-agent-games-signature"] = hmacHex(HMAC_SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;
    const timer = setTimeout(() => {
      if (!done) { done = true; reject(new Error("request body timeout")); }
    }, 55000);
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        clearTimeout(timer);
        if (!done) { done = true; reject(new Error("request body too large")); }
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(Buffer.concat(chunks));
    });
    req.on("error", (e) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      reject(e);
    });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  try {
    if (req.method === "GET" && (url.pathname === "/health" || url.pathname === "/")) {
      return sendJson(res, 200, {
        status: "ok",
        agent: AGENT,
        track: TRACK,
        circuit: "gatekeeper",
        vkHash: VK_HASH_HEX,
        hmacConfigured: Boolean(HMAC_SECRET),
      });
    }

    if (req.method === "POST" && (url.pathname === "/" || url.pathname === "/task")) {
      if (!HMAC_SECRET) {
        // Fail closed: without the platform secret we cannot verify tasks.
        return sendJson(res, 503, { error: "hmac_secret_not_configured" });
      }
      const rawBody = await readRawBody(req);
      const sig =
        req.headers["x-agent-games-signature"] ||
        req.headers["x-signature"] ||
        req.headers["x-hmac-signature"];
      if (!verifyHmac(HMAC_SECRET, rawBody, Array.isArray(sig) ? sig[0] : sig)) {
        console.log(`[reject] bad/missing HMAC signature`);
        return sendJson(res, 401, { error: "invalid_signature" });
      }
      let body;
      try {
        body = JSON.parse(rawBody.toString("utf8"));
      } catch {
        return sendJson(res, 400, { error: "invalid_json" });
      }
      const task = extractTask(body);
      let decided;
      try {
        decided = decide(task);
      } catch (e) {
        // Malformed task: fail closed, no decision issued.
        return sendJson(res, 400, { error: "invalid_task", detail: String(e.message).slice(0, 200) });
      }
      console.log(`[task] id=${decided.taskIdRaw} decision=${decided.decision} checks=${JSON.stringify(decided.checks)}`);
      let proofOut;
      try {
        proofOut = await generateProof(decided.input);
      } catch (e) {
        // Proof generation failed (incl. circuit refusing a wrong decision,
        // or timeout): fail closed, no decision returned.
        console.log(`[task] proof failed for id=${decided.taskIdRaw}: ${String(e.message).slice(0, 160)}`);
        return sendJson(res, 503, { error: "proof_failed", detail: "fail closed" });
      }
      return sendJson(res, 200, {
        agent: AGENT,
        track: TRACK,
        circuit: "gatekeeper",
        circuitVersion: "gatekeeper",
        taskId: decided.taskIdRaw,
        decision: decided.decision,
        checks: decided.checks,
        vkHash: VK_HASH_HEX,
        proof: proofOut.proof,
        publicSignals: proofOut.publicSignals,
        generatedAt: new Date().toISOString(),
      }, true);
    }

    return sendJson(res, 404, { error: "not_found" });
  } catch (e) {
    console.error("[error]", String(e && e.message ? e.message : e).slice(0, 300));
    if (!res.headersSent) return sendJson(res, 500, { error: "internal_error" });
    try { res.end(); } catch { /* ignore */ }
  }
});

server.listen(PORT, () => {
  console.log(`[${AGENT}] proof-gatekeeper agent listening on http://localhost:${PORT}`);
  console.log(`[${AGENT}] endpoints: GET /health, POST / (task envelope)`);
});
