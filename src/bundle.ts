import { z } from "zod";
import { hashJson } from "./rules";

const addr = z.string().regex(/^0x[0-9a-fA-F]{40}$/).transform((a) => a.toLowerCase() as `0x${string}`);
const hex = z.string().regex(/^0x([0-9a-fA-F]{2})*$/) as z.ZodType<`0x${string}`>;

export const call = z
  .object({
    to: addr.optional(),
    create: hex.optional(),
    data: hex.default("0x"),
    value: z.string().regex(/^\d+$/).default("0"),
  })
  .refine((c) => Boolean(c.to) !== Boolean(c.create), "a call has exactly one of `to` or `create`");

export const claim = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("invariant"), invariantId: z.string() }),
  z.object({ kind: z.literal("balance"), token: z.union([z.literal("eth"), addr]) }),
]);

// The attacker starts with this much ETH and nothing else: enough for gas and msg.value,
// nothing a real unprivileged account could not also hold.
export const ATTACKER_ETH = 1000n * 10n ** 18n;
export const MAX_CALLS = 24;

export const bundle = z.object({
  version: z.literal(1),
  chainId: z.number().int(),
  target: addr,
  forkBlock: z.number().int().nonnegative(),
  attacker: addr,
  calls: z.array(call).min(1).max(MAX_CALLS),
  claim,
});

export type Bundle = z.infer<typeof bundle>;
export type BundleCall = z.infer<typeof call>;

export const bundleHash = (b: Bundle) => hashJson(bundle.parse(b));
