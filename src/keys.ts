/**
 * Lebrel's Ed25519 signing key, pinned in every client. It signs the runtime's
 * encryption configuration, the serving manifest and every response receipt.
 * Trust is application configuration, never data obtained from an endpoint.
 */
export const LEBREL_SIGNING_PUBLIC_KEY_BASE64 = "beFZtSwt6FnlhIYbX636n7w3/gpaASIkRnIMx52XJwk=";
/** SHA-256 of the raw 32-byte public key, as published in `signing_key_id` fields. */
export const LEBREL_SIGNING_KEY_ID = "8f72beb9680a0f1911dce59d1fc103a0a89039998003715d35422d3020e5292d";
