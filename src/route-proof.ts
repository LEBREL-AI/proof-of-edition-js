/**
 * Proof of Edition for routed models. A route manifest names where a model ID is forwarded (the lab's own
 * API), the pricing contract and the verification board; a route receipt binds one answer to that manifest,
 * to the upstream that served it and to the verdict the board held at the time. Both are signed by the
 * router's key and checked with the same canonical form and Ed25519 signatures as edition documents.
 * A route receipt proves where a request went and what the last probe said; it does not prove which
 * weights answered. This module runs in the browser, in tests and in the Worker.
 */
import {
  decodeSigningKey, keyId, manifestIdentity, sha256Hex, verifySignature,
  type JsonValue, type ProofCheck, type SignedDocument,
} from "./proof-of-edition.js";

export const ROUTE_DOCUMENT_VERSION = 2;
export const ROUTER_ORIGIN = "https://router.lebrel.ai";
export const ROUTE_BOARD_URL = "https://models.lebrel.ai/watch";
/** The router's Ed25519 signing key (hex) and its ID (SHA-256 of the raw key), pinned like Lebrel's runtime key. */
export const ROUTER_SIGNING_KEY_HEX = "f7dd66b73acc863219b339c789fd25e63fa75304365eaa6a0c7a9080b7dbfb87";
export const ROUTER_SIGNING_KEY_ID = "5973b84bda22bd938b29c4b4f4596515fcb95d5be43d02905d30b6366e50ed59";
export const ROUTER_SIGNING_KEY = decodeSigningKey(ROUTER_SIGNING_KEY_HEX);
/** Router request IDs, as returned in X-Request-ID and named by route receipts. */
export const ROUTE_REQUEST_ID = /^req_[0-9a-f]{32}$/u;

export function routeSlug(modelId: string): string {
  return modelId.replace(/\//gu, "--");
}

export function routeManifestUrl(modelId: string, origin = ROUTER_ORIGIN): string {
  return `${origin}/m/${routeSlug(modelId)}/.well-known/proof-of-edition`;
}

export function routeReceiptUrl(requestId: string, origin = ROUTER_ORIGIN): string {
  return `${origin}/v1/receipts/${encodeURIComponent(requestId)}`;
}

export function isRouteDocument(document: SignedDocument): boolean {
  return document.payload.kind === "route";
}

const ROUTE_MANIFEST_REQUIRED = [
  "version", "kind", "model_id", "level", "family", "claimed_revision", "upstreams", "pricing",
  "billing_contract_hash", "data_note", "verification_board", "claims", "issued_at", "expires_at", "signing_key_id",
] as const;
const ROUTE_RECEIPT_REQUIRED = [
  "version", "kind", "request_id", "model_id", "manifest_sha256", "upstream", "upstream_model", "served_model",
  "provider", "verification", "prompt_sha256", "response_sha256", "prompt_tokens", "completion_tokens",
  "cached_tokens", "usage_exact", "price_microusd", "fee_bps", "pricing_tier", "multiplier_percent", "streamed",
  "issued_at", "instance_id", "signing_key_id",
] as const;

function isRecord(value: unknown): value is Record<string, JsonValue> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
function text(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= 2_048 ? value : null;
}
function integer(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}
function hex64(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
}

export type RouteUpstream = Readonly<{ name: string; model: string; note: string | null }>;
import type { RouteFingerprint, RoutePeak } from "./route-copy.js";
export type RoutePricingSummary = Readonly<{
  inputMicrousdPerMillionTokens: number;
  cachedInputMicrousdPerMillionTokens: number;
  outputMicrousdPerMillionTokens: number;
  feeBps: number | null;
  peak: RoutePeak | null;
}>;
export type RouteManifestSummary = Readonly<{
  identity: string;
  modelId: string | null;
  family: string | null;
  level: number | null;
  claimedRevision: string | null;
  upstreams: RouteUpstream[];
  pricing: RoutePricingSummary | null;
  billingContractHash: string | null;
  dataNote: string | null;
  claims: string | null;
  boardUrl: string | null;
  issuedAt: number;
  expiresAt: number;
  signingKeyId: string | null;
}>;
export type RouteVerdict = Readonly<{ status: string; runId: string | null; checkedAt: number | null; fingerprint: RouteFingerprint | null }>;
export type RouteReceiptSummary = Readonly<{
  requestId: string | null;
  modelId: string | null;
  upstream: string | null;
  upstreamModel: string | null;
  servedModel: string | null;
  provider: string | null;
  /** The lab's own id for the answer and the backend configuration it reported, when it gives them. */
  upstreamResponseId: string | null;
  upstreamSystemFingerprint: string | null;
  verification: RouteVerdict | null;
  promptTokens: number | null;
  completionTokens: number | null;
  cachedTokens: number | null;
  usageExact: boolean;
  priceMicrousd: number | null;
  feeBps: number | null;
  pricingTier: string | null;
  multiplierPercent: number | null;
  streamed: boolean;
  issuedAt: number | null;
  manifestSha256: string | null;
  promptSha256: string | null;
  responseSha256: string | null;
  signingKeyId: string | null;
}>;

export function parseRouteUpstreams(value: unknown): RouteUpstream[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry) => {
    if (!isRecord(entry)) return [];
    const name = text(entry.name);
    const model = text(entry.model);
    return name && model ? [{ name, model, note: text(entry.data_note) }] : [];
  });
}

export function parseRoutePeak(value: unknown): RoutePeak | null {
  if (!isRecord(value)) return null;
  const multiplierPercent = integer(value.multiplier_percent);
  if (multiplierPercent === null) return null;
  const weekdays = Array.isArray(value.weekdays) ? value.weekdays.flatMap((day) => (integer(day) !== null ? [day as number] : [])) : [];
  const windowsUtc = Array.isArray(value.windows_utc)
    ? value.windows_utc.flatMap((window): [string, string][] => Array.isArray(window) && window.length === 2 && typeof window[0] === "string" && typeof window[1] === "string" ? [[window[0], window[1]]] : [])
    : [];
  const holidaysUtc = Array.isArray(value.holidays_utc) ? value.holidays_utc.flatMap((day) => (typeof day === "string" ? [day] : [])) : [];
  return { multiplierPercent, weekdays, windowsUtc, holidaysUtc };
}

function parseFingerprint(value: unknown): RouteFingerprint | null {
  if (!isRecord(value)) return null;
  const verdict = text(value.verdict);
  if (!verdict) return null;
  const bps = integer(value.similarity_bps);
  const checked = integer(value.checked_at);
  return {
    verdict,
    similarityPercent: bps === null ? null : bps / 100,
    checkedAt: checked === null ? null : new Date(checked * 1000).toISOString(),
    receiptsVerified: integer(value.receipts_verified) ?? 0,
    receiptsTotal: integer(value.receipts_total) ?? 0,
    compared: (integer(value.compared) ?? 0) > 0 ? integer(value.compared) : null,
    weightsVerdict: text(value.weights_verdict) || null,
  };
}

function parseVerdict(value: unknown): RouteVerdict | null {
  if (!isRecord(value)) return null;
  const status = text(value.status);
  return status ? { status, runId: text(value.run_id), checkedAt: integer(value.checked_at), fingerprint: parseFingerprint(value.fingerprint) } : null;
}

export async function summarizeRouteManifest(document: SignedDocument): Promise<RouteManifestSummary> {
  const payload = document.payload;
  const pricing = isRecord(payload.pricing) ? payload.pricing : null;
  const input = pricing ? integer(pricing.input_microusd_per_million_tokens) : null;
  const cached = pricing ? integer(pricing.cached_input_microusd_per_million_tokens) : null;
  const output = pricing ? integer(pricing.output_microusd_per_million_tokens) : null;
  return Object.freeze({
    identity: await manifestIdentity(payload),
    modelId: text(payload.model_id),
    family: text(payload.family),
    level: integer(payload.level),
    claimedRevision: text(payload.claimed_revision),
    upstreams: parseRouteUpstreams(payload.upstreams),
    pricing: pricing && input !== null && cached !== null && output !== null
      ? { inputMicrousdPerMillionTokens: input, cachedInputMicrousdPerMillionTokens: cached, outputMicrousdPerMillionTokens: output, feeBps: integer(pricing.fee_bps), peak: parseRoutePeak(pricing.peak) }
      : null,
    billingContractHash: hex64(payload.billing_contract_hash) ? payload.billing_contract_hash : null,
    dataNote: text(payload.data_note),
    claims: text(payload.claims),
    boardUrl: text(payload.verification_board),
    issuedAt: integer(payload.issued_at) ?? 0,
    expiresAt: integer(payload.expires_at) ?? 0,
    signingKeyId: text(payload.signing_key_id),
  });
}

export function summarizeRouteReceipt(document: SignedDocument): RouteReceiptSummary {
  const payload = document.payload;
  return Object.freeze({
    requestId: text(payload.request_id),
    modelId: text(payload.model_id),
    upstream: text(payload.upstream),
    upstreamModel: text(payload.upstream_model),
    servedModel: text(payload.served_model),
    provider: text(payload.provider),
    upstreamResponseId: text(payload.upstream_response_id),
    upstreamSystemFingerprint: text(payload.upstream_system_fingerprint),
    verification: parseVerdict(payload.verification),
    promptTokens: integer(payload.prompt_tokens),
    completionTokens: integer(payload.completion_tokens),
    cachedTokens: integer(payload.cached_tokens),
    usageExact: payload.usage_exact === true,
    priceMicrousd: integer(payload.price_microusd),
    feeBps: integer(payload.fee_bps),
    pricingTier: text(payload.pricing_tier),
    multiplierPercent: integer(payload.multiplier_percent),
    streamed: payload.streamed === true,
    issuedAt: integer(payload.issued_at),
    manifestSha256: hex64(payload.manifest_sha256) ? payload.manifest_sha256 : null,
    promptSha256: hex64(payload.prompt_sha256) ? payload.prompt_sha256 : null,
    responseSha256: hex64(payload.response_sha256) ? payload.response_sha256 : null,
    signingKeyId: text(payload.signing_key_id),
  });
}

export type RouteManifestCheckOptions = { publicKey?: Uint8Array; nowSeconds?: number };

/** Mirrors `check_route_manifest` in the Python reference. All checks run; each reports its own result. */
export async function checkRouteManifest(document: SignedDocument, options: RouteManifestCheckOptions = {}): Promise<ProofCheck[]> {
  const publicKey = options.publicKey ?? ROUTER_SIGNING_KEY;
  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const payload = document.payload;
  const missing = ROUTE_MANIFEST_REQUIRED.filter((field) => !(field in payload));
  const expectedKeyId = await keyId(publicKey);
  const issuedAt = integer(payload.issued_at);
  const expiresAt = integer(payload.expires_at);
  const upstreams = parseRouteUpstreams(payload.upstreams);
  const shapeOk = missing.length === 0 && payload.version === ROUTE_DOCUMENT_VERSION && payload.kind === "route";
  const windowOk = issuedAt !== null && expiresAt !== null && issuedAt - 60 <= now && now <= expiresAt;
  return [
    { id: "shape", label: "Route manifest fields", ok: shapeOk, detail: missing.length ? `Missing: ${missing.join(", ")}` : shapeOk ? `Route document, version ${String(payload.version)}` : "Not a route manifest" },
    { id: "key", label: "Signing key", ok: payload.signing_key_id === expectedKeyId, detail: payload.signing_key_id === expectedKeyId ? `Pinned router key ${expectedKeyId.slice(0, 16)}…` : "Signed by a key this client does not pin" },
    { id: "signature", label: "Signature", ok: verifySignature(document, publicKey), detail: "Ed25519 over the canonical manifest" },
    { id: "window", label: "Validity window", ok: windowOk, detail: issuedAt !== null && expiresAt !== null ? (windowOk ? "Current at the time of this check" : "Outside its validity window") : "No validity window" },
    { id: "upstreams", label: "Named upstream", ok: upstreams.length > 0, detail: upstreams.length ? upstreams.map((upstream) => `${upstream.name} · ${upstream.model}`).join(", ") : "The manifest names no upstream" },
    { id: "contract", label: "Billing contract", ok: hex64(payload.billing_contract_hash), detail: hex64(payload.billing_contract_hash) ? `Contract ${payload.billing_contract_hash.slice(0, 16)}… pinned in the manifest` : "No billing contract hash" },
  ];
}

export type RouteReceiptCheckOptions = {
  publicKey?: Uint8Array;
  /** The request body exactly as sent, when available. */
  prompt?: Uint8Array | string;
  /** The assistant text exactly as received, concatenated across stream deltas. */
  response?: string;
  /** The receipt is only meaningful against the route manifest it was issued under. */
  manifest?: SignedDocument;
  manifestIdentity?: string;
};

/** Mirrors `check_route_receipt` in the Python reference. */
export async function checkRouteReceipt(document: SignedDocument, options: RouteReceiptCheckOptions = {}): Promise<ProofCheck[]> {
  const publicKey = options.publicKey ?? ROUTER_SIGNING_KEY;
  const payload = document.payload;
  const missing = ROUTE_RECEIPT_REQUIRED.filter((field) => !(field in payload));
  const expectedKeyId = await keyId(publicKey);
  const shapeOk = missing.length === 0 && payload.version === ROUTE_DOCUMENT_VERSION && payload.kind === "route";
  const checks: ProofCheck[] = [
    { id: "shape", label: "Route receipt fields", ok: shapeOk, detail: missing.length ? `Missing: ${missing.join(", ")}` : shapeOk ? `Route document, version ${String(payload.version)}` : "Not a route receipt" },
    { id: "key", label: "Signing key", ok: payload.signing_key_id === expectedKeyId, detail: payload.signing_key_id === expectedKeyId ? `Pinned router key ${expectedKeyId.slice(0, 16)}…` : "Signed by a key this client does not pin" },
    { id: "signature", label: "Signature", ok: verifySignature(document, publicKey), detail: "Ed25519 over the canonical receipt" },
  ];
  const identity = options.manifestIdentity ?? (options.manifest ? await manifestIdentity(options.manifest.payload) : undefined);
  if (identity !== undefined) {
    const ok = payload.manifest_sha256 === identity;
    checks.push({ id: "manifest", label: "Route manifest", ok, detail: ok ? `Matches manifest ${identity.slice(0, 16)}…` : "The receipt references a different manifest" });
  }
  if (options.manifest) {
    const upstreams = parseRouteUpstreams(options.manifest.payload.upstreams);
    const sameModel = text(options.manifest.payload.model_id) !== null && options.manifest.payload.model_id === payload.model_id;
    const named = upstreams.some((upstream) => upstream.name === payload.upstream && upstream.model === payload.upstream_model);
    checks.push({ id: "route", label: "Route consistency", ok: sameModel && named, detail: sameModel && named ? `${String(payload.upstream)} serves ${String(payload.model_id)} in the manifest` : sameModel ? "The receipt names an upstream the manifest does not" : "The receipt is for a different model ID" });
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

export { ROUTE_VERIFICATION, describePeak, feePercent, routeVerification, type RoutePeak } from "./route-copy.js";
