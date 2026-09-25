# lebrel-proof-of-edition

Verify what answered you. Lebrel signs a **serving manifest** (which weights, at which precision, on which
engine and tokenizer are serving) and a **receipt for every answer** (the SHA-256 of your request as sent,
the SHA-256 of the answer, the manifest it ran under, the token counts). This package runs the same checks
as [lebrel.ai/verify](https://lebrel.ai/verify), in Node 20+ or a browser, with Lebrel's keys pinned.

```sh
npm install lebrel-proof-of-edition
```

## Verify an answer from a routed model

Routed models (a lab's own API behind Lebrel's router) take plain OpenAI-format requests. Every answer
carries the router's signed route receipt: where the request went, the lab's own record of the answer,
the board's verdict at that moment, and the digests of your request and the answer.

```ts
import { verifyRouteAnswer } from "lebrel-proof-of-edition";

const model = "deepseek/deepseek-v4.1-flash";
const body = JSON.stringify({ model, messages: [{ role: "user", content: "Name one color." }] });
const response = await fetch("https://api.lebrel.ai/v1/chat/completions", {
  method: "POST",
  headers: { Authorization: `Bearer ${process.env.LEBREL_API_KEY}`, "Content-Type": "application/json" },
  body,
});
const answer = await response.json();
const result = await verifyRouteAnswer(response.headers.get("X-Request-ID")!, model, {
  request: body,                                 // exactly the bytes you sent
  response: answer.choices[0].message.content,   // exactly the text you received
});
console.log(result.verified);                    // true: signature, manifest, route and both digests
for (const check of result.checks) console.log(check.ok ? "ok  " : "FAIL", check.label, check.detail);
```

## Verify a receipt you already hold

A plain answer carries its receipt in the `Proof-Of-Edition-Receipt` header (base64 of the signed JSON);
a streamed answer's receipt is fetched afterwards by request id. Both paths give a signed document:

```ts
import { parseReceiptHeader, fetchServingManifest, verifyReceipt } from "lebrel-proof-of-edition";

const receipt = parseReceiptHeader(response.headers.get("Proof-Of-Edition-Receipt")!);
const manifest = await fetchServingManifest();  // https://api.lebrel.ai/.well-known/proof-of-edition
const result = await verifyReceipt(receipt, manifest, { request: body, response: text });
```

For a Lebrel edition (served on Lebrel's own runtime, end-to-end encrypted), the
[Python client](https://github.com/LEBREL-AI/lebrel-encrypted-python) fetches and checks receipts itself;
this package checks the same documents in JavaScript: `verifyAnswer(requestId, { request, response })`.

## What the checks say

- `key`, `signature`: the document is signed by the pinned key (Lebrel's runtime key for editions, the router's
  key for routed models). Pass `publicKey` to pin another.
- `manifest`: the receipt names the manifest that is serving now (its identity is the digest of the manifest
  without its validity window, so hourly republication does not break the link).
- `route`: the receipt's upstream and model are the ones the route manifest declares.
- `prompt`, `response`: the digests match what you sent and what you received.
- The manifest's own checks (fields, key, signature, validity window, weight digests) are appended when one
  of them fails, so `verified` always explains itself.

An edition receipt proves that Lebrel's runtime signed a commitment binding your request and the answer to a
manifest whose weights are published with their hashes. A route receipt proves where a request went and what
the verification board said at the time; it does not by itself prove which weights answered — that is what
the board at [models.lebrel.ai/watch](https://models.lebrel.ai/watch) measures, hour by hour.

## Lower-level API

`parseSignedDocument`, `canonicalJson`, `verifySignature`, `manifestIdentity`, `checkManifest`, `checkReceipt`,
`summarizeManifest`, `checkRouteManifest`, `checkRouteReceipt`, `summarizeRouteManifest`,
`summarizeRouteReceipt`, and the pinned keys `LEBREL_SIGNING_KEY` / `ROUTER_SIGNING_KEY` with their ids.
Canonical JSON is byte-identical to the Python reference (`json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=False)`); signatures are Ed25519 over it.

The standard, the Python verifier and the watch are at
[github.com/LEBREL-AI/proof-of-edition](https://github.com/LEBREL-AI/proof-of-edition).

Questions and security reports: contact@lebrel.ai. Apache-2.0, Lebrel AI LLC.
