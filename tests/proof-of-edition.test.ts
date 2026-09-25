import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";
import nacl from "tweetnacl";
import {
  allPassed, canonicalJson, checkManifest, checkReceipt, decodeSigningKey, keyId, manifestIdentity,
  parseSignedDocument, summarizeManifest, verifySignature, LEBREL_SIGNING_KEY, precisionLabel, engineLabel, attestationLabel,
} from "../src/proof-of-edition.js";
import { LEBREL_SIGNING_KEY_ID } from "../src/keys.js";
import { recordedReceipt, recordedStreamReceipt, signedTestManifest, RECORDED_MANIFEST_IDENTITY, RECORDED_PROMPT_TEXT, RECORDED_ANSWER_TEXT } from "./fixtures/evidence.js";

test("the pinned signing key has the published key id", async () => {
  assert.equal(await keyId(LEBREL_SIGNING_KEY), LEBREL_SIGNING_KEY_ID);
  assert.deepEqual(decodeSigningKey(LEBREL_SIGNING_KEY_ID.length === 64 ? Buffer.from(LEBREL_SIGNING_KEY).toString("hex") : ""), LEBREL_SIGNING_KEY);
});

test("canonical JSON matches the Python reference byte for byte", async () => {
  const sample = { z: [1, "two", null, true, { b: "ñ \"quoted\" \n\t", a: 0 }], "é": "ü", A: -5 };
  const expected = canonicalJson(sample as never);
  const script = "import json,sys; print(json.dumps(json.loads(sys.stdin.read()), sort_keys=True, separators=(',', ':'), ensure_ascii=False), end='')";
  let python: string | null = null;
  try {
    python = execFileSync("python3", ["-c", script], { encoding: "utf8", input: JSON.stringify(sample), timeout: 10_000 });
  } catch {
    // Python is optional in CI; the recorded production signatures below cover the same property.
  }
  if (python !== null) assert.equal(expected, python);
  assert.equal(expected, '{"A":-5,"z":[1,"two",null,true,{"a":0,"b":"ñ \\"quoted\\" \\n\\t\\u0001"}],"é":"ü"}');
  assert.throws(() => canonicalJson({ x: 1.5 } as never), /floating point/u);
});

test("a signed manifest verifies against the key that signed it, inside its window", async () => {
  const { manifest, publicKey } = await signedTestManifest();
  const issuedAt = manifest.payload.issued_at as number;
  const checks = await checkManifest(manifest, { publicKey, nowSeconds: issuedAt + 60 });
  assert.ok(allPassed(checks), JSON.stringify(checks));
  const expired = await checkManifest(manifest, { publicKey, nowSeconds: issuedAt + 7 * 24 * 3600 });
  assert.equal(expired.find((check) => check.id === "window")?.ok, false);
  assert.equal(expired.find((check) => check.id === "signature")?.ok, true);
  const pinned = await checkManifest(manifest, { nowSeconds: issuedAt + 60 });
  assert.equal(pinned.find((check) => check.id === "key")?.ok, false, "a manifest from another key fails against Lebrel's pinned key");
  assert.equal(pinned.find((check) => check.id === "signature")?.ok, false);
  const summary = await summarizeManifest(manifest);
  assert.equal(summary.edition.id, "lebrel/example-edition");
  assert.equal(summary.weights.fileCount, 3);
  assert.equal(summary.weights.revision?.length, 40);
  assert.equal(summary.identity, await manifestIdentity(manifest.payload));
  assert.equal(precisionLabel(summary), "NVFP4");
  assert.match(engineLabel(summary), /^SGLang 0\.5\.18$/u);
  assert.equal(attestationLabel(summary), null);
});

test("both recorded production receipts verify against the pinned key and bind the manifest, the request and the answer", async () => {
  const checks = await checkReceipt(recordedReceipt, { manifestIdentity: RECORDED_MANIFEST_IDENTITY, prompt: RECORDED_PROMPT_TEXT, response: RECORDED_ANSWER_TEXT });
  assert.ok(allPassed(checks), JSON.stringify(checks));
  assert.equal(checks.length, 6);
  const stream = await checkReceipt(recordedStreamReceipt, { manifestIdentity: RECORDED_MANIFEST_IDENTITY });
  assert.ok(allPassed(stream), JSON.stringify(stream));
  const wrongAnswer = await checkReceipt(recordedReceipt, { manifestIdentity: RECORDED_MANIFEST_IDENTITY, response: "RECEIPT_OK." });
  assert.equal(wrongAnswer.find((check) => check.id === "response")?.ok, false);
  const otherManifest = await checkReceipt(recordedReceipt, { manifestIdentity: "0".repeat(64) });
  assert.equal(otherManifest.find((check) => check.id === "manifest")?.ok, false);
});

test("a receipt from another key or with an altered payload is rejected", async () => {
  const other = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(3));
  const forged = { payload: { ...recordedReceipt.payload, completion_tokens: 500 }, signature: recordedReceipt.signature };
  assert.equal(verifySignature(forged, LEBREL_SIGNING_KEY), false);
  const resignedPayload = { ...forged.payload, signing_key_id: await keyId(other.publicKey) };
  const resigned = { payload: resignedPayload, signature: Buffer.from(nacl.sign.detached(Buffer.from(canonicalJson(resignedPayload)), other.secretKey)).toString("base64") };
  const checks = await checkReceipt(resigned, { manifestIdentity: RECORDED_MANIFEST_IDENTITY });
  assert.equal(checks.find((check) => check.id === "key")?.ok, false);
  assert.equal(checks.find((check) => check.id === "signature")?.ok, false);
  assert.equal(allPassed(checks), false);
});

test("pasted documents are bounded and shape-checked", () => {
  assert.throws(() => parseSignedDocument("not json"), /valid JSON/u);
  assert.throws(() => parseSignedDocument(JSON.stringify({ payload: "x", signature: "" })), /payload object/u);
  assert.throws(() => parseSignedDocument(JSON.stringify({ payload: {}, signature: "AAAA" })), /length|base64/u);
  assert.throws(() => parseSignedDocument("x".repeat(70_000)), /too large/u);
  const parsed = parseSignedDocument(JSON.stringify(recordedReceipt));
  assert.equal(parsed.signature, recordedReceipt.signature);
});
