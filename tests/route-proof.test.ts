/**
 * Route documents from the production router, verified with the pinned router key exactly as the
 * verify page and the docs promise: signatures, manifest identity, route consistency and the digests
 * of the request and the answer that produced the recorded receipt.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import nacl from "tweetnacl";
import { allPassed, keyId, parseSignedDocument } from "../src/proof-of-edition.js";
import { routeFingerprint } from "../src/route-copy.js";
import {
  ROUTER_SIGNING_KEY, ROUTER_SIGNING_KEY_ID, ROUTE_REQUEST_ID, checkRouteManifest, checkRouteReceipt, describePeak,
  isRouteDocument, routeManifestUrl, routeReceiptUrl, routeVerification, summarizeRouteManifest, summarizeRouteReceipt,
} from "../src/route-proof.js";

const fixture = (name: string) => readFile(new URL(`./fixtures/route/${name}`, import.meta.url), "utf8");

test("the pinned router key has the published key id", async () => {
  assert.equal(await keyId(ROUTER_SIGNING_KEY), ROUTER_SIGNING_KEY_ID);
});

test("a production route manifest and receipt verify against the pinned router key, with the exact request and answer", async () => {
  const manifest = parseSignedDocument(await fixture("manifest.json"));
  const receipt = parseSignedDocument(await fixture("receipt.json"));
  assert.ok(isRouteDocument(manifest) && isRouteDocument(receipt));
  const summary = await summarizeRouteManifest(manifest);
  const manifestChecks = await checkRouteManifest(manifest, { nowSeconds: summary.issuedAt + 60 });
  assert.ok(allPassed(manifestChecks), JSON.stringify(manifestChecks.filter((check) => !check.ok)));
  assert.equal(summary.modelId, "deepseek/deepseek-v4.1-flash");
  assert.deepEqual(summary.upstreams.map((upstream) => upstream.name), ["deepseek/api"]);
  assert.equal(summary.pricing?.feeBps, 500);
  assert.equal(summary.pricing?.peak?.multiplierPercent, 200);
  assert.equal(describePeak(summary.pricing?.peak), "×2 on weekdays 01:00–04:00 and 06:00–10:00 UTC, except 8 listed holidays");
  const checks = await checkRouteReceipt(receipt, { manifest, prompt: await fixture("request.json"), response: await fixture("answer.txt") });
  assert.ok(allPassed(checks), JSON.stringify(checks.filter((check) => !check.ok)));
  assert.deepEqual(checks.map((check) => check.id), ["shape", "key", "signature", "manifest", "route", "prompt", "response"]);
  const facts = summarizeRouteReceipt(receipt);
  assert.match(facts.requestId ?? "", ROUTE_REQUEST_ID);
  assert.equal(facts.upstream, "deepseek/api");
  assert.equal(facts.servedModel, "deepseek-flash");
  assert.equal(facts.priceMicrousd, 3);
  assert.equal(facts.pricingTier, "standard");
  assert.equal(facts.multiplierPercent, 100);
  assert.equal(facts.usageExact, true);
  assert.equal(facts.verification?.status, "unverified");
  assert.equal(facts.manifestSha256, summary.identity);
});

test("a tampered receipt, a foreign key, a wrong answer and a manifest for another route all fail their own check", async () => {
  const manifest = parseSignedDocument(await fixture("manifest.json"));
  const receipt = parseSignedDocument(await fixture("receipt.json"));
  const tampered = parseSignedDocument({ payload: { ...receipt.payload, price_microusd: 1 }, signature: receipt.signature });
  const tamperedChecks = await checkRouteReceipt(tampered, { manifest });
  assert.equal(tamperedChecks.find((check) => check.id === "signature")?.ok, false);
  const foreign = nacl.sign.keyPair().publicKey;
  const foreignChecks = await checkRouteReceipt(receipt, { publicKey: foreign });
  assert.equal(foreignChecks.find((check) => check.id === "key")?.ok, false);
  assert.equal(foreignChecks.find((check) => check.id === "signature")?.ok, false);
  const wrongAnswer = await checkRouteReceipt(receipt, { manifest, response: "not ready" });
  assert.equal(wrongAnswer.find((check) => check.id === "response")?.ok, false);
  const otherRoute = parseSignedDocument({ payload: { ...manifest.payload, model_id: "deepseek/deepseek-v4-pro" }, signature: manifest.signature });
  const mismatch = await checkRouteReceipt(receipt, { manifest: otherRoute });
  assert.equal(mismatch.find((check) => check.id === "manifest")?.ok, false);
  assert.equal(mismatch.find((check) => check.id === "route")?.ok, false);
  const expired = await checkRouteManifest(manifest, { nowSeconds: (manifest.payload.expires_at as number) + 1 });
  assert.equal(expired.find((check) => check.id === "window")?.ok, false);
});

test("route URLs and the board vocabulary", () => {
  assert.equal(routeManifestUrl("deepseek/deepseek-v4.1-flash"), "https://router.lebrel.ai/m/deepseek--deepseek-v4.1-flash/.well-known/proof-of-edition");
  assert.equal(routeReceiptUrl("req_" + "a".repeat(32)), `https://router.lebrel.ai/v1/receipts/req_${"a".repeat(32)}`);
  assert.equal(routeVerification("consistent").tone, "ok");
  assert.equal(routeVerification("divergent").tone, "warn");
  assert.equal(routeVerification(null).label, "Not probed");
  assert.equal(describePeak(null), "");
  assert.equal(describePeak({ multiplierPercent: 100, weekdays: [], windowsUtc: [["01:00", "02:00"]], holidaysUtc: [] }), "");
});

test("a route receipt names the lab's own record and carries the route fingerprint of its time", () => {
  const facts = summarizeRouteReceipt({ payload: { kind: "route", upstream_response_id: "3444f6fa-7dcc-4537-8d71-a87ae90cb9cc", upstream_system_fingerprint: "aeb56401ca74e127821c4f9126dcb669",
    verification: { status: "consistent", run_id: "r", checked_at: 1, fingerprint: { verdict: "match", similarity_bps: 10000, compared: 27, weights_verdict: "within_margin", run_id: "f", checked_at: 1_790_259_900, receipts_verified: 48, receipts_total: 48 } } }, signature: "x" });
  assert.equal(facts.upstreamResponseId, "3444f6fa-7dcc-4537-8d71-a87ae90cb9cc");
  assert.equal(facts.upstreamSystemFingerprint, "aeb56401ca74e127821c4f9126dcb669");
  assert.equal(facts.verification?.fingerprint?.similarityPercent, 100);
  assert.equal(facts.verification?.fingerprint?.receiptsTotal, 48);
  assert.equal(routeFingerprint(facts.verification?.fingerprint)?.label, "Identical to the lab's API 100%");
  assert.equal(routeFingerprint(facts.verification?.fingerprint)?.meaning,
    "answers through the route carry the same first-word probabilities as the lab's own API; 48 of 48 receipts verified; 27 prompts compared, checked 24 Sep 14:25 UTC",
    "the percentage carries its n and its hour");
  assert.equal(facts.verification?.fingerprint?.weightsVerdict, "within_margin");
});
