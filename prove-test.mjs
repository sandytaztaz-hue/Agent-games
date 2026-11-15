// Proof test: valid scenario must prove + verify OK; wrong decision must FAIL to prove.
import * as snarkjs from "snarkjs";
import fs from "fs";

const VK_HASH_HEX = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const VK_HASH_DEC = BigInt(VK_HASH_HEX).toString(); // reduced mod p by the witness calc
const ADDR_A = BigInt("0x1111111111111111111111111111111111111111").toString();
const ADDR_B = BigInt("0x2222222222222222222222222222222222222222").toString();

const vkey = JSON.parse(fs.readFileSync("circuits/verification_key.json", "utf8"));

function baseInput() {
  return {
    registeredVkHash: VK_HASH_DEC,
    proofVkHash: VK_HASH_DEC,
    minimum: "1000",
    publicBalance: "1460",
    expiryBlock: "8430000",
    currentBlock: "8420000",
    recipient: ADDR_A,
    conditionRecipient: ADDR_A,
    amount: "500",
    maxTransfer: "1000",
    decision: "1",
    taskId: "1",
    salt: "123456789",
  };
}

async function tryProve(label, input) {
  console.log("\n=== " + label + " ===");
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      "circuits/gatekeeper.wasm",
      "circuits/gatekeeper_final.zkey"
    );
    console.log("fullProve: SUCCEEDED");
    console.log("publicSignals:", JSON.stringify(publicSignals));
    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    console.log("groth16 verify:", ok ? "OK" : "FAIL");
    fs.writeFileSync(`test_${label.replace(/[^a-z0-9]+/gi, "_")}_proof.json`, JSON.stringify({ proof, publicSignals }, null, 2));
    return { proved: true, verified: ok, publicSignals };
  } catch (e) {
    console.log("fullProve: FAILED —", String(e && e.message ? e.message : e).split("\n")[0]);
    return { proved: false, verified: false };
  }
}

// 1. VALID: all checks pass, decision=1 -> must prove + verify OK
const valid = await tryProve("valid_approve", baseInput());

// 2. INVALID: recipient mismatch but decision=1 -> must FAIL to prove
const bad = baseInput();
bad.recipient = ADDR_B; // mismatch vs conditionRecipient
bad.decision = "1";
const invalid = await tryProve("invalid_approve_mismatch", bad);

// 3. CORRECT REJECTION: recipient mismatch, decision=0 -> must prove + verify OK
const rej = baseInput();
rej.recipient = ADDR_B;
rej.decision = "0";
const reject = await tryProve("correct_reject_mismatch", rej);

// 4. INVALID: all checks pass but decision=0 -> must FAIL to prove
const bad2 = baseInput();
bad2.decision = "0";
const invalid2 = await tryProve("invalid_reject_valid", bad2);

console.log("\n=== SUMMARY ===");
console.log("valid approve proves+verifies:", valid.proved && valid.verified ? "PASS" : "FAIL");
console.log("wrong approve fails to prove:", !invalid.proved ? "PASS" : "FAIL");
console.log("correct reject proves+verifies:", reject.proved && reject.verified ? "PASS" : "FAIL");
console.log("wrong reject fails to prove:", !invalid2.proved ? "PASS" : "FAIL");

process.exit(0);
