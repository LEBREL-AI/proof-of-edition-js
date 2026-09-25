/** Words for routed models that every page shares: the board vocabulary and the peak-hour sentence. Pure, no crypto. */
export type RoutePeak = Readonly<{ multiplierPercent: number; weekdays: number[]; windowsUtc: [string, string][]; holidaysUtc: string[] }>;

/** The sentence the reader needs next to a board status; the vocabulary of the watch board. */
export const ROUTE_VERIFICATION: Record<string, { tone: "ok" | "warn" | "muted"; label: string; meaning: string }> = {
  consistent: { tone: "ok", label: "Consistent", meaning: "agrees with the compared deployments within the published thresholds" },
  suspect: { tone: "warn", label: "Suspect", meaning: "one of the two tests disagrees; another run is needed before any conclusion" },
  drift: { tone: "warn", label: "Drift", meaning: "this endpoint changed against its own previous run with the same battery" },
  divergent: { tone: "warn", label: "Divergent", meaning: "beyond the implementation margin of the lab's own API or of the published weights, or against the majority of hosts serving the same model" },
  disputed: { tone: "warn", label: "Disputed", meaning: "two hosts disagree and there is no third one to break the tie" },
  unverified: { tone: "muted", label: "Unverified", meaning: "probed, but nothing to compare against yet" },
  insufficient: { tone: "muted", label: "Insufficient", meaning: "too few calls to say anything" },
  error: { tone: "warn", label: "Probe errors", meaning: "most probes failed" },
};

export function routeVerification(status: string | null | undefined): { tone: "ok" | "warn" | "muted"; label: string; meaning: string } {
  return (status && ROUTE_VERIFICATION[status]) || { tone: "muted", label: "Not probed", meaning: "no board entry for this upstream yet" };
}

/** "×2 on weekdays 01:00–04:00 and 06:00–10:00 UTC"; empty when there is no surcharge. */
export function describePeak(peak: RoutePeak | null | undefined): string {
  if (!peak || peak.multiplierPercent === 100 || !peak.windowsUtc.length) return "";
  const days = peak.weekdays.length === 0 || peak.weekdays.length === 7 ? "every day" : peak.weekdays.length === 5 && peak.weekdays.every((day) => day >= 1 && day <= 5) ? "on weekdays" : `on days ${peak.weekdays.join(", ")}`;
  const windows = peak.windowsUtc.map(([from, to]) => `${from}–${to}`).join(" and ");
  const factor = peak.multiplierPercent % 100 === 0 ? `×${peak.multiplierPercent / 100}` : `×${(peak.multiplierPercent / 100).toFixed(2)}`;
  const holidays = peak.holidaysUtc.length ? `, except ${peak.holidaysUtc.length} listed holidays` : "";
  return `${factor} ${days} ${windows} UTC${holidays}`;
}

/** "5%" from basis points, without trailing zeros. */
export function feePercent(bps: number): string {
  const percent = bps / 100;
  return `${Number.isInteger(percent) ? percent : percent.toFixed(2)}%`;
}

/** The watch's hourly fingerprint of Lebrel's own route: the first word's probabilities against the lab's own API. */
export type RouteFingerprint = Readonly<{
  verdict: string;
  similarityPercent: number | null;
  checkedAt: string | null;
  receiptsVerified: number;
  receiptsTotal: number;
  /** Prompts the verdict rests on in that check; null when the board did not say. */
  compared: number | null;
  /** What the watch found when it ran the weights the lab published and compared the lab's own API with them; null when no such run exists yet. */
  weightsVerdict: string | null;
}>;

/** The lab's own API against Lebrel's run of the weights the lab published: the half of the check that says which weights answer. */
export const WEIGHTS_VERDICT: Record<string, { tone: "ok" | "warn" | "muted"; label: string; meaning: string }> = {
  within_margin: { tone: "ok", label: "Published weights: within the margin", meaning: "the lab's own API answers inside the implementation margin of Lebrel's run of the weights the lab published" },
  at_margin: { tone: "warn", label: "Published weights: at the margin", meaning: "the lab's own API sits at the edge of the implementation margin of the published weights; more hours decide" },
  outside_margin: { tone: "warn", label: "Published weights: outside the margin", meaning: "the lab's own API answers beyond what another implementation of the published weights produces" },
  insufficient: { tone: "muted", label: "Published weights: too few hours", meaning: "Lebrel's run of the published weights needs more hours of the lab's answers to compare" },
  sampled_match: { tone: "ok", label: "Published weights: same first words", meaning: "the first words of the lab's own API are drawn from the same distribution as Lebrel's run of the weights the lab published, estimated by sampling" },
  sampled_differs: { tone: "warn", label: "Published weights: sampled words differ", meaning: "the lab's own API's first words sit further from Lebrel's run of the published weights than chance explains; the next run decides" },
  sampled_mismatch: { tone: "warn", label: "Published weights: not the same words", meaning: "the lab's own API's first words are not those of Lebrel's run of the published weights" },
};

/** The published-weights chip of a route: the verdict when Lebrel has run the lab's published weights, and an honest "not yet" otherwise. */
export function routeWeights(fingerprint: RouteFingerprint | null | undefined): { tone: "ok" | "warn" | "muted"; label: string; meaning: string } | null {
  if (!fingerprint) return null;
  if (!fingerprint.weightsVerdict) {
    return { tone: "muted", label: "No published-weights reference yet", meaning: "Lebrel has not yet run the weights this lab published, so the route is compared with the lab's own API only" };
  }
  return WEIGHTS_VERDICT[fingerprint.weightsVerdict] ?? { tone: "muted", label: "Published weights: checked", meaning: "compared with Lebrel's run of the published weights" };
}

export const ROUTE_FINGERPRINT: Record<string, { tone: "ok" | "warn" | "muted"; label: string; meaning: string }> = {
  match: { tone: "ok", label: "Identical to the lab's API", meaning: "answers through the route carry the same first-word probabilities as the lab's own API" },
  differs: { tone: "warn", label: "Fingerprint differs", meaning: "the probabilities are further from the lab's own API than its own hourly variation; the next hourly check decides" },
  mismatch: { tone: "warn", label: "Not identical to the lab's API", meaning: "the probabilities or the token counts are not the lab's own API's" },
  receipt_failed: { tone: "warn", label: "Receipt check failed", meaning: "a signed route receipt did not verify in the last check" },
  no_logprobs: { tone: "muted", label: "No fingerprint", meaning: "the route returned no token probabilities" },
  insufficient: { tone: "muted", label: "Fingerprint pending", meaning: "too few answers in the last check" },
  // by sampling: the lab returns no probabilities, so the first word of many answers is counted instead
  sampled_match: { tone: "ok", label: "Same first words as the lab's API", meaning: "the first words of answers through the route are drawn from the same distribution as the lab's own API, estimated by sampling because the lab returns no probabilities" },
  sampled_differs: { tone: "warn", label: "Sampled fingerprint differs", meaning: "the sampled first words sit further from the lab's own API than chance explains; the next check decides" },
  sampled_mismatch: { tone: "warn", label: "Not the lab's API's first words", meaning: "the sampled first words or the token counts are not the lab's own API's" },
};

export function routeFingerprint(fingerprint: RouteFingerprint | null | undefined): { tone: "ok" | "warn" | "muted"; label: string; meaning: string } | null {
  if (!fingerprint) return null;
  const words = ROUTE_FINGERPRINT[fingerprint.verdict] ?? { tone: "muted" as const, label: "Fingerprint", meaning: "checked by the watch" };
  const percent = fingerprint.similarityPercent === null ? "" : ` ${fingerprint.similarityPercent % 1 === 0 ? fingerprint.similarityPercent.toFixed(0) : fingerprint.similarityPercent.toFixed(2)}%`;
  const receipts = fingerprint.receiptsTotal ? `; ${fingerprint.receiptsVerified} of ${fingerprint.receiptsTotal} receipts verified` : "";
  const basis = fingerprintBasis(fingerprint);
  return { tone: words.tone, label: `${words.label}${percent}`, meaning: `${words.meaning}${receipts}${basis ? `; ${basis}` : ""}` };
}

/** What the percentage rests on and when: "31 prompts compared, checked 25 Sep 12:05 UTC". A number without its n and its hour is not evidence. */
export function fingerprintBasis(fingerprint: RouteFingerprint): string {
  const parts: string[] = [];
  if (fingerprint.compared) parts.push(`${fingerprint.compared} prompt${fingerprint.compared === 1 ? "" : "s"} compared`);
  const stamp = fingerprint.checkedAt ? utcStamp(fingerprint.checkedAt) : "";
  if (stamp) parts.push(`checked ${stamp}`);
  return parts.join(", ");
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
/** "25 Sep 12:05 UTC", the same on the server and in every browser. */
function utcStamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return `${date.getUTCDate()} ${MONTHS[date.getUTCMonth()]} ${String(date.getUTCHours()).padStart(2, "0")}:${String(date.getUTCMinutes()).padStart(2, "0")} UTC`;
}
