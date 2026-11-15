// Local end-to-end test of server.mjs (spawns it, hits it, verifies everything).
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import * as snarkjs from "snarkjs";

const SECRET = "testsecret123";
const PORT = 3000;
const BASE = `http://localhost:${PORT}`;
const vkey = JSON.parse(fs.readFileSync("circuits/verification_key.json", "utf8"));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let pass = 0, fail = 0;
function check(name, ok, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? " — " + extra : ""}`);
  ok ? pass++ : fail++;
}
function sign(body) {
  return crypto.createHmac("sha256", SECRET).update(body).digest("hex");
}

const server = spawn("node", ["server.mjs"], {
  env: { ...process.env, PORT: String(PORT), HMAC_SECRET: SECRET },
  stdio: ["ignore", "pipe", "pipe"],
});
let serverLog = "";
server.stdout.on("data", (d) => (serverLog += d));
server.stderr.on("data", (d) => (serverLog += d));

try {
  // Wait for health
  let healthy = false;
  for (let i = 0; i < 15; i++) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) { healthy = true; break; }
    } catch { /* retry */ }
    await sleep(500);
  }
  check("server becomes healthy", healthy);
  const health = await (await fetch(`${BASE}/health`)).json();
  check("health reports hmacConfigured=true", health.hmacConfigured === true, JSON.stringify(health));

  const validTask = {
    minimum: 1000, publicBalance: 1460, amount: 500, maxTransfer: 1000,
    recipient: "0x1111111111111111111111111111111111111111",
    conditionRecipient: "0x1111111111111111111111111111111111111111",
    expiryBlock: 8430000, currentBlock: 8420000, taskId: "test-1",
  };

  // 1. Valid approve, correct HMAC
  const body1 = JSON.stringify(validTask);
  const r1 = await fetch(`${BASE}/`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sign(body1) },
    body: body1,
  });
  const raw1 = await r1.text();
  const j1 = JSON.parse(raw1);
  check("valid task -> 200", r1.status === 200, `status ${r1.status}`);
  check("decision is 1 (approve)", j1.decision === 1, `decision=${j1.decision}`);
  check("response carries proof + publicSignals", !!j1.proof && Array.isArray(j1.publicSignals) && j1.publicSignals.length === 13);
  const sig1 = r1.headers.get("x-agent-games-signature");
  check("response is HMAC-signed (header present)", !!sig1);
  check("response signature verifies", sig1 === sign(raw1), `header=${String(sig1).slice(0, 16)}...`);
  const ok1 = await snarkjs.groth16.verify(vkey, j1.publicSignals, j1.proof);
  check("returned proof verifies locally", ok1 === true);

  // 2. Wrong HMAC -> 401
  const r2 = await fetch(`${BASE}/`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": "deadbeef" },
    body: body1,
  });
  check("wrong HMAC -> 401", r2.status === 401, `status ${r2.status}`);

  // 3. Missing HMAC -> 401
  const r3 = await fetch(`${BASE}/`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: body1,
  });
  check("missing HMAC -> 401", r3.status === 401, `status ${r3.status}`);

  // 4. Reject task (recipient mismatch) -> decision 0 + valid proof
  const rejectTask = { ...validTask, recipient: "0x2222222222222222222222222222222222222222", taskId: "test-2" };
  const body4 = JSON.stringify(rejectTask);
  const r4 = await fetch(`${BASE}/task`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sign(body4) },
    body: body4,
  });
  const j4 = await r4.json();
  check("reject task -> 200", r4.status === 200, `status ${r4.status}`);
  check("decision is 0 (reject)", j4.decision === 0, `decision=${j4.decision}`);
  const ok4 = await snarkjs.groth16.verify(vkey, j4.publicSignals, j4.proof);
  check("reject proof verifies locally", ok4 === true);

  // 5. Malformed task (missing fields) -> 400
  const badTask = { minimum: 1000, taskId: "test-3" };
  const body5 = JSON.stringify(badTask);
  const r5 = await fetch(`${BASE}/`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sign(body5) },
    body: body5,
  });
  check("malformed task -> 400", r5.status === 400, `status ${r5.status}`);

  // 6. Nested envelope shape works
  const nested = { task: validTask };
  const body6 = JSON.stringify(nested);
  const r6 = await fetch(`${BASE}/`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sign(body6) },
    body: body6,
  });
  const j6 = await r6.json();
  check("nested {task:{...}} envelope -> decision 1", r6.status === 200 && j6.decision === 1, `status ${r6.status} decision=${j6.decision}`);

  console.log(`\nserver log:\n${serverLog}`);
  console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
} finally {
  server.kill("SIGTERM");
  setTimeout(() => process.exit(fail === 0 ? 0 : 1), 500);
}
