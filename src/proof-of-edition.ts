/**
 * Proof of Edition, client side: the signed serving manifest and per-response receipts
 * that let anyone check which weights, precision and engine produced an answer.
 *
 * Reference implementation: proof-of-edition/receipts/schema.py (Python) and the Go
 * sidecar's canonical.go. Documents are JSON objects signed with Ed25519 over their
 * canonical form: keys sorted by code point, no whitespace, raw UTF-8, integers only.
 * This module runs in the browser, in tests and in the Worker; it has no DOM dependency.
 */
import nacl from "tweetnacl";
import { LEBREL_SIGNING_KEY_ID, LEBREL_SIGNING_PUBLIC_KEY_BASE64 } from "./keys.js";

export const MANIFEST_VERSION = 1;
export const RECEIPT_VERSION = 1;
/** Receipts and manifests are small; a bound keeps pasted or relayed input honest. */
export const MAX_DOCUMENT_BYTES = 65_536;

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type SignedDocument = Readonly<{ payload: Record<string, JsonValue>; signature: string }>;

export type ManifestEdition = { id: string; name: string | null; baseModel: string | null; fingerprintId: string | null };
export type ManifestSummary = Readonly<{
  identity: string;
  edition: ManifestEdition;
  weights: { repository: string | null; revision: string | null; fileCount: number; totalBytes: number | null };
  quantization: { method: string | null; weightsDtype: string | null; kvCacheDtype: string | null };
  engine: { name: string | null; version: string | null; imageDigest: string | null };
  tokenizerSha256: string | null;
  chatTemplateSha256: string | null;
  runtime: { provider: string | null; instanceId: string | null; sidecarSha256: string | null };
  attestation: Record<string, JsonValue> | null;
  issuedAt: number;
  expiresAt: number;
  signingKeyId: string | null;
}>;

export type ProofCheck = Readonly<{ id: string; label: string; ok: boolean; detail: string }>;

const MANIFEST_REQUIRED = [
  "version", "edition", "weights", "quantization", "engine", "tokenizer_sha256",
  "chat_template_sha256", "runtime", "attestation", "issued_at", "expires_at", "signing_key_id",
] as const;
const RECEIPT_REQUIRED = [
  "version", "request_id", "manifest_sha256", "prompt_sha256", "response_sha256",
  "prompt_tokens", "completion_tokens", "issued_at", "instance_id", "signing_key_id",
] as const;

const encoder = new TextEncoder();

function isRecord(value: unknown): value is Record<string, JsonValue> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

/** Python `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`, byte for byte. */
export function canonicalJson(value: JsonValue): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean": return value ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(value)) throw new Error("canonical JSON does not allow floating point numbers");
      return String(value);
    case "string": return JSON.stringify(value);
    default: break;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) {
    const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key] as JsonValue)}`).join(",")}}`;
  }
  throw new Error("canonical JSON does not support this value type");
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  const digest = await crypto.subtle.digest("SHA-256", new Uint8Array(bytes).buffer as ArrayBuffer);
  return bytesToHex(new Uint8Array(digest));
}

export function decodeBase64(value: string, expectedLength?: number): Uint8Array {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    throw new Error("Invalid base64 value");
  }
  const decoded = atob(value);
  if (btoa(decoded) !== value) throw new Error("Invalid base64 value");
  const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  if (expectedLength !== undefined && bytes.length !== expectedLength) throw new Error("Unexpected base64 length");
  return bytes;
}

/** The key clients trust. Supplied as base64 (SDK form) or 64 hex characters (CLI form). */
export function decodeSigningKey(value: string): Uint8Array {
  const trimmed = value.trim();
  if (/^[0-9a-f]{64}$/iu.test(trimmed)) {
    return Uint8Array.from(trimmed.match(/.{2}/gu)!, (pair) => Number.parseInt(pair, 16));
  }
  return decodeBase64(trimmed, 32);
}

export const LEBREL_SIGNING_KEY = decodeSigningKey(LEBREL_SIGNING_PUBLIC_KEY_BASE64);

export async function keyId(publicKey: Uint8Array): Promise<string> {
  return sha256Hex(publicKey);
}

/** Parses a signed document from JSON text or an already parsed value, with bounds. */
export function parseSignedDocument(input: unknown): SignedDocument {
  let value: unknown = input;
  if (typeof input === "string") {
    if (encoder.encode(input).byteLength > MAX_DOCUMENT_BYTES) throw new Error("Document is too large");
    try { value = JSON.parse(input); } catch { throw new Error("Document is not valid JSON"); }
  }
  if (!isRecord(value) || !isRecord(value.payload) || typeof value.signature !== "string") {
    throw new Error("Document must contain a payload object and a signature");
  }
  decodeBase64(value.signature, 64);
  return Object.freeze({ payload: value.payload, signature: value.signature });
}

export function verifySignature(document: SignedDocument, publicKey: Uint8Array): boolean {
  try {
    const message = encoder.encode(canonicalJson(document.payload));
    return nacl.sign.detached.verify(message, decodeBase64(document.signature, 64), publicKey);
  } catch {
    return false;
  }
}

/** Digest of the manifest without its validity window: stable across hourly republication. */
export async function manifestIdentity(payload: Record<string, JsonValue>): Promise<string> {
  const identity: Record<string, JsonValue> = {};
  for (const [key, value] of Object.entries(payload)) {
    if (key !== "issued_at" && key !== "expires_at") identity[key] = value;
  }
  return sha256Hex(canonicalJson(identity));
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= 512 ? value : null;
}
function integer(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}
function nested(value: unknown, key: string): unknown {
  return isRecord(value) ? value[key] : undefined;
}

export async function summarizeManifest(document: SignedDocument): Promise<ManifestSummary> {
  const payload = document.payload;
  const edition = payload.edition;
  const weights = payload.weights;
  const files = nested(weights, "files");
  const quantization = payload.quantization;
  const engine = payload.engine;
  const runtime = payload.runtime;
  const attestation = isRecord(payload.attestation) ? payload.attestation : null;
  return Object.freeze({
    identity: await manifestIdentity(payload),
    edition: {
      id: text(isRecord(edition) ? edition.id : edition) ?? "unknown",
      name: text(nested(edition, "name")),
      baseModel: text(nested(edition, "base_model")),
      fingerprintId: text(nested(edition, "fingerprint_id")),
    },
    weights: {
      repository: text(nested(weights, "repository")),
      revision: text(nested(weights, "revision")),
      fileCount: isRecord(files) ? Object.keys(files).length : 0,
      totalBytes: integer(nested(weights, "total_bytes")),
    },
    quantization: {
      method: text(nested(quantization, "method")),
      weightsDtype: text(nested(quantization, "weights_dtype")),
      kvCacheDtype: text(nested(quantization, "kv_cache_dtype")),
    },
    engine: {
      name: text(nested(engine, "name")),
      version: text(nested(engine, "version")),
      imageDigest: text(nested(engine, "image_digest")),
    },
    tokenizerSha256: text(payload.tokenizer_sha256),
    chatTemplateSha256: text(payload.chat_template_sha256),
    runtime: {
      provider: text(nested(runtime, "provider")),
      instanceId: text(nested(runtime, "instance_id")),
      sidecarSha256: text(nested(nested(runtime, "sidecar"), "binary_sha256")),
    },
    attestation,
    issuedAt: integer(payload.issued_at) ?? 0,
    expiresAt: integer(payload.expires_at) ?? 0,
    signingKeyId: text(payload.signing_key_id),
  });
}

export type ManifestCheckOptions = { publicKey?: Uint8Array; nowSeconds?: number };

/** Mirrors `check_manifest` in the Python reference. All checks run; each reports its own result. */
export async function checkManifest(document: SignedDocument, options: ManifestCheckOptions = {}): Promise<ProofCheck[]> {
  const publicKey = options.publicKey ?? LEBREL_SIGNING_KEY;
  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const payload = document.payload;
  const missing = MANIFEST_REQUIRED.filter((field) => !(field in payload));
  const expectedKeyId = await keyId(publicKey);
  const issuedAt = integer(payload.issued_at);
  const expiresAt = integer(payload.expires_at);
  const files = nested(payload.weights, "files");
  const fileDigestsValid = isRecord(files) && Object.keys(files).length > 0
    && Object.values(files).every((value) => typeof value === "string" && /^[0-9a-f]{64}$/u.test(value));
  const revision = nested(payload.weights, "revision");
  return [
    { id: "shape", label: "Manifest fields", ok: missing.length === 0 && payload.version === MANIFEST_VERSION, detail: missing.length ? `Missing: ${missing.join(", ")}` : `Version ${String(payload.version)}` },
    { id: "key", label: "Signing key", ok: payload.signing_key_id === expectedKeyId, detail: payload.signing_key_id === expectedKeyId ? `Pinned key ${expectedKeyId.slice(0, 16)}…` : "Signed by a key this client does not trust" },
    { id: "signature", label: "Signature", ok: verifySignature(document, publicKey), detail: "Ed25519 over the canonical manifest" },
    { id: "window", label: "Validity window", ok: issuedAt !== null && expiresAt !== null && issuedAt - 60 <= now && now <= expiresAt, detail: issuedAt !== null && expiresAt !== null ? `${formatUtc(issuedAt)} → ${formatUtc(expiresAt)} UTC` : "Window missing" },
    { id: "weights", label: "Weight digests", ok: fileDigestsValid && typeof revision === "string" && revision.length === 40, detail: fileDigestsValid ? `${Object.keys(files as object).length} files pinned by SHA-256` : "Weight files must map to SHA-256 digests" },
  ];
}

export type ReceiptCheckOptions = {
  publicKey?: Uint8Array;
  /** The plaintext request body exactly as sent, when available. */
  prompt?: Uint8Array | string;
  /** The assistant text exactly as received, concatenated across stream deltas. */
  response?: string;
  /** The receipt is only meaningful against the manifest it was issued under. */
  manifest?: SignedDocument;
  manifestIdentity?: string;
};

/** Mirrors `check_receipt` in the Python reference. */
export async function checkReceipt(document: SignedDocument, options: ReceiptCheckOptions = {}): Promise<ProofCheck[]> {
  const publicKey = options.publicKey ?? LEBREL_SIGNING_KEY;
  const payload = document.payload;
  const missing = RECEIPT_REQUIRED.filter((field) => !(field in payload));
  const expectedKeyId = await keyId(publicKey);
  const checks: ProofCheck[] = [
    { id: "shape", label: "Receipt fields", ok: missing.length === 0 && payload.version === RECEIPT_VERSION, detail: missing.length ? `Missing: ${missing.join(", ")}` : `Version ${String(payload.version)}` },
    { id: "key", label: "Signing key", ok: payload.signing_key_id === expectedKeyId, detail: payload.signing_key_id === expectedKeyId ? `Pinned key ${expectedKeyId.slice(0, 16)}…` : "Signed by a key this client does not trust" },
    { id: "signature", label: "Signature", ok: verifySignature(document, publicKey), detail: "Ed25519 over the canonical receipt" },
  ];
  const identity = options.manifestIdentity ?? (options.manifest ? await manifestIdentity(options.manifest.payload) : undefined);
  if (identity !== undefined) {
    const ok = payload.manifest_sha256 === identity;
    checks.push({ id: "manifest", label: "Serving manifest", ok, detail: ok ? `Matches manifest ${identity.slice(0, 16)}…` : "The receipt references a different manifest" });
  }
  if (options.prompt !== undefined) {
    const digest = await sha256Hex(options.prompt);
    const ok = payload.prompt_sha256 === digest;
    checks.push({ id: "prompt", label: "Your request", ok, detail: ok ? `SHA-256 ${digest.slice(0, 16)}… matches` : "The request digest does not match what was sent" });
  }
  if (options.response !== undefined) {
    const digest = await sha256Hex(options.response);
    const ok = payload.response_sha256 === digest;
    checks.push({ id: "response", label: "The answer", ok, detail: ok ? `SHA-256 ${digest.slice(0, 16)}… matches` : "The answer digest does not match what was received" });
  }
  return checks;
}

export function allPassed(checks: readonly ProofCheck[]): boolean {
  return checks.length > 0 && checks.every((check) => check.ok);
}

export function formatUtc(seconds: number): string {
  const date = new Date(seconds * 1000);
  return `${date.toISOString().slice(0, 10)} ${date.toISOString().slice(11, 16)}`;
}

export function shortHex(value: string | null | undefined, length = 12): string {
  if (!value) return "—";
  return value.length > length ? `${value.slice(0, length)}…` : value;
}

export function formatBytes(bytes: number | null): string {
  if (bytes === null) return "—";
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(0)} MB`;
  return `${bytes} B`;
}

/** Display names for manifest values, so the UI never repeats internal spellings. */
export function precisionLabel(summary: Pick<ManifestSummary, "quantization">): string {
  const method = summary.quantization.method ?? summary.quantization.weightsDtype;
  return method ? method.toUpperCase() : "—";
}

export function engineLabel(summary: Pick<ManifestSummary, "engine">): string {
  const name = summary.engine.name;
  if (!name) return "—";
  const pretty = name === "sglang" ? "SGLang" : name === "vllm" ? "vLLM" : name;
  return summary.engine.version ? `${pretty} ${summary.engine.version}` : pretty;
}

export function attestationLabel(summary: Pick<ManifestSummary, "attestation">): string | null {
  const attestation = summary.attestation;
  if (!attestation) return null;
  const kind = text(attestation.type) ?? text(attestation.kind) ?? text(attestation.platform);
  return kind ? `Attested · ${kind}` : "Attested hardware";
}

export const LEBREL_SIGNING_KEY_ID_PINNED = LEBREL_SIGNING_KEY_ID;
