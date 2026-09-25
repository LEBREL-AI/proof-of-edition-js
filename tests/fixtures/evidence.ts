/**
 * Two receipts recorded from api.lebrel.ai on 22 September 2026, issued by the production
 * runtime and captured by the encrypted Python SDK: real documents, real signatures by
 * Lebrel's pinned key. Both reference the manifest they ran under by its identity digest.
 *
 * The non-streaming request asked the model to reply with exactly "RECEIPT_OK" and the
 * streaming one with "STREAM_OK"; the receipts carry only the digests of both exchanges.
 *
 * The manifest checks run against a manifest with the same fields the runtime signs, signed
 * here by a test key.
 */
import nacl from "tweetnacl";
import { canonicalJson, keyId, type SignedDocument } from "../../src/proof-of-edition.js";

export const RECORDED_AT = "2026-09-22";
export const RECORDED_PROMPT_TEXT = "{\"model\":\"lebrel/deepseek-v4-flash-uncensored\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with exactly: RECEIPT_OK\"}],\"max_tokens\":16,\"temperature\":0,\"stream\":false}";
export const RECORDED_ANSWER_TEXT = "RECEIPT_OK";
/** Identity of the serving manifest both recorded receipts were issued under. */
export const RECORDED_MANIFEST_IDENTITY = "3175dbcce0de35126d3b34aa15674248ea12243ff4aa9af201d80ebb0777ee3f";

export const recordedReceipt: SignedDocument = {
  "payload": {
    "completion_tokens": 5,
    "instance_id": "d02d3f1e9fce79e4ae14381f48495002",
    "issued_at": 1790093235,
    "manifest_sha256": "3175dbcce0de35126d3b34aa15674248ea12243ff4aa9af201d80ebb0777ee3f",
    "prompt_sha256": "422eaadd209d5f7bd53be3cd53014374f137dbd75501e7407b2875d412e23234",
    "prompt_tokens": 12,
    "request_id": "6d566ed8-f5db-4360-9eee-7e70664cb38e",
    "response_sha256": "6c366db592fd6d82c7da8d38c4c420f74a9258978887882d1bcb3e840a374db7",
    "signing_key_id": "8f72beb9680a0f1911dce59d1fc103a0a89039998003715d35422d3020e5292d",
    "version": 1
  },
  "signature": "cmx3M+noysihaYR34UKKh7h95Ci3OqY+1TYcDJ5m+sCQGan3iyhVGkhKBgEXKuT0q+eOq+Ssb2w+N67ixUS9CQ=="
};

export const recordedStreamReceipt: SignedDocument = {
  "payload": {
    "completion_tokens": 4,
    "instance_id": "d02d3f1e9fce79e4ae14381f48495002",
    "issued_at": 1790093241,
    "manifest_sha256": "3175dbcce0de35126d3b34aa15674248ea12243ff4aa9af201d80ebb0777ee3f",
    "prompt_sha256": "2b1771bf04da5dd7b5c9bdad109cdd270310b7ef0546c072ce5d014e3b6302ee",
    "prompt_tokens": 11,
    "request_id": "8053d488-fe4e-45d7-b780-ed1cd552fe37",
    "response_sha256": "2de1bc1a458e4ab478860007f3c71e7592e7e21af35261eca7b1c1cbdcd31274",
    "signing_key_id": "8f72beb9680a0f1911dce59d1fc103a0a89039998003715d35422d3020e5292d",
    "version": 1
  },
  "signature": "gaEDW8aGRZBDKU5SzqYFCvsFrOj75x3dKkgb2/sAXFi7Npnfp80g8mRbW7fLFukm+/Ib8xrTFzLq8Rx8pX9JDg=="
};

/** A serving manifest with every field the runtime signs, signed by a fixed test key. */
export async function signedTestManifest(): Promise<{ manifest: SignedDocument; publicKey: Uint8Array }> {
  const pair = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(7));
  const payload = {
    version: 1,
    signing_key_id: await keyId(pair.publicKey),
    issued_at: 1_790_092_800,
    expires_at: 1_790_096_400,
    edition: { id: "lebrel/example-edition", name: "Lebrel Example Edition", base_model: "example/Base-Model", fingerprint_id: null, recipe: null },
    weights: {
      repository: "models.lebrel.ai/lebrel/example-edition",
      revision: "c".repeat(40),
      total_bytes: 3_000,
      files: { "config.json": "1".repeat(64), "model-00001-of-00002.safetensors": "2".repeat(64), "model-00002-of-00002.safetensors": "3".repeat(64) },
    },
    quantization: { method: "nvfp4", weights_dtype: "nvfp4", kv_cache_dtype: "fp8_e4m3" },
    engine: { name: "sglang", version: "0.5.18", image_digest: `sha256:${"4".repeat(64)}`, arguments: ["--tp", "1"], arguments_sha256: "5".repeat(64) },
    tokenizer_sha256: "6".repeat(64),
    chat_template_sha256: "7".repeat(64),
    chat_template_source: "chat_template.jinja",
    runtime: { encryption: "ehbp-hpke-x25519-aes256gcm", gpu: "B300", gpu_count: 1 },
    attestation: null,
  };
  const signature = Buffer.from(nacl.sign.detached(new TextEncoder().encode(canonicalJson(payload)), pair.secretKey)).toString("base64");
  return { manifest: { payload, signature }, publicKey: pair.publicKey };
}
