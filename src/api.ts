/**
 * Fetch-and-check helpers over the verifier: the receipt of an answer, the manifest it names, and every check
 * that the request and the answer you hold allow. Works wherever `fetch` and WebCrypto exist (Node 20+, browsers).
 */
import {
  allPassed, checkManifest, checkReceipt, decodeBase64, parseSignedDocument,
  type ProofCheck, type SignedDocument,
} from "./proof-of-edition.js";
import { checkRouteManifest, checkRouteReceipt, routeManifestUrl, routeReceiptUrl, ROUTER_ORIGIN } from "./route-proof.js";

export const LEBREL_API_ORIGIN = "https://api.lebrel.ai";
/** The response header that carries the signed receipt of a plain (non-streaming) answer, base64 of its JSON. */
export const RECEIPT_HEADER = "Proof-Of-Edition-Receipt";

export type Verification = Readonly<{
  receipt: SignedDocument;
  manifest: SignedDocument | null;
  /** Every check that ran, the receipt's first; a failed manifest check is appended so `verified` explains itself. */
  checks: ProofCheck[];
  verified: boolean;
}>;

export type VerifyOptions = Readonly<{
  /** The request body exactly as sent (bytes or the exact JSON string). */
  request?: Uint8Array | string;
  /** The assistant text exactly as received; for a stream, every content delta concatenated in order. */
  response?: string;
  /** Skip fetching the manifest: the receipt's signature and digests are checked, not what it ran on. */
  manifest?: boolean;
  origin?: string;
  fetch?: typeof fetch;
  nowSeconds?: number;
}>;

async function fetchSigned(url: string, fetchImpl: typeof fetch): Promise<SignedDocument> {
  const response = await fetchImpl(url, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${url} answered HTTP ${response.status}`);
  return parseSignedDocument(await response.text());
}

/** The receipt an answer carried in its `Proof-Of-Edition-Receipt` header. */
export function parseReceiptHeader(value: string): SignedDocument {
  const bytes = decodeBase64(value.trim());
  return parseSignedDocument(new TextDecoder().decode(bytes));
}

/** The signed serving manifest of a Lebrel edition: what is serving right now. */
export function fetchServingManifest(origin = LEBREL_API_ORIGIN, fetchImpl: typeof fetch = fetch): Promise<SignedDocument> {
  return fetchSigned(`${origin}/.well-known/proof-of-edition`, fetchImpl);
}

/** The receipt of an answer by its request id (`X-Request-ID`, or the `X-Lebrel-Request-Id` you sent). */
export function fetchReceipt(requestId: string, origin = LEBREL_API_ORIGIN, fetchImpl: typeof fetch = fetch): Promise<SignedDocument> {
  return fetchSigned(`${origin}/v1/receipts/${encodeURIComponent(requestId)}`, fetchImpl);
}

/**
 * Fetch and check the receipt of an answer from a Lebrel edition: the pinned key and signature, the manifest
 * serving now, and, when given, the digests of the request as sent and of the answer as received.
 */
export async function verifyAnswer(requestId: string, options: VerifyOptions = {}): Promise<Verification> {
  const origin = options.origin ?? LEBREL_API_ORIGIN;
  const fetchImpl = options.fetch ?? fetch;
  const receipt = await fetchReceipt(requestId, origin, fetchImpl);
  return verifyReceipt(receipt, options.manifest === false ? null : await fetchServingManifest(origin, fetchImpl), options);
}

/** Check a receipt you already hold (from the header or a file) against a manifest and what you sent and received. */
export async function verifyReceipt(receipt: SignedDocument, manifest: SignedDocument | null, options: Pick<VerifyOptions, "request" | "response" | "nowSeconds"> = {}): Promise<Verification> {
  const checks = await checkReceipt(receipt, { manifest: manifest ?? undefined, prompt: options.request, response: options.response });
  const manifestChecks = manifest ? await checkManifest(manifest, { nowSeconds: options.nowSeconds }) : [];
  return {
    receipt, manifest,
    checks: [...checks, ...manifestChecks.filter((check) => !check.ok)],
    verified: allPassed(checks) && (manifest === null || allPassed(manifestChecks)),
  };
}

/**
 * Fetch and check the receipt of an answer from a routed model (a lab's own API behind Lebrel's router): the
 * pinned router key and signature, the route manifest of that model, the route named in it, and your digests.
 */
export async function verifyRouteAnswer(requestId: string, modelId: string, options: VerifyOptions = {}): Promise<Verification> {
  const origin = options.origin ?? ROUTER_ORIGIN;
  const fetchImpl = options.fetch ?? fetch;
  const receipt = await fetchSigned(routeReceiptUrl(requestId, origin), fetchImpl);
  const manifest = options.manifest === false ? null : await fetchSigned(routeManifestUrl(modelId, origin), fetchImpl);
  return verifyRouteReceipt(receipt, manifest, options);
}

/** Check a route receipt you already hold against its route manifest and what you sent and received. */
export async function verifyRouteReceipt(receipt: SignedDocument, manifest: SignedDocument | null, options: Pick<VerifyOptions, "request" | "response" | "nowSeconds"> = {}): Promise<Verification> {
  const checks = await checkRouteReceipt(receipt, { manifest: manifest ?? undefined, prompt: options.request, response: options.response });
  const manifestChecks = manifest ? await checkRouteManifest(manifest, { nowSeconds: options.nowSeconds }) : [];
  return {
    receipt, manifest,
    checks: [...checks, ...manifestChecks.filter((check) => !check.ok)],
    verified: allPassed(checks) && (manifest === null || allPassed(manifestChecks)),
  };
}
