import { decodeFunctionResult, encodeFunctionData, keccak256, parseAbiItem, toBytes, type AbiFunction, type Address, type Hex, type PublicClient } from "viem";
import { z } from "zod";

const addr = z.string().regex(/^0x[0-9a-fA-F]{40}$/);

const operand = z.union([
  z.object({ call: z.object({ target: addr, fn: z.string().min(10), args: z.array(z.string()).default([]) }) }),
  z.object({ const: z.string().regex(/^-?\d+$/) }),
]);

export const rule = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]{1,63}$/),
  description: z.string().min(4).max(240),
  lhs: operand,
  op: z.enum(["==", "!=", ">=", "<=", ">", "<"]),
  rhs: operand,
  severity: z.enum(["Critical", "High", "Medium", "Low"]).optional(),
});

export type Rule = z.infer<typeof rule>;
export type Operand = z.infer<typeof operand>;
export type Evaluation = { id: string; holds: boolean; lhs: string; rhs: string };

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined).sort(([a], [b]) => (a < b ? -1 : 1));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export const canonicalJson = canonical;
export const hashJson = (value: unknown) => keccak256(toBytes(canonical(value)));

export function normalize(r: Rule): Rule {
  const norm = (o: Operand): Operand => ("call" in o ? { call: { ...o.call, target: o.call.target.toLowerCase(), fn: o.call.fn.trim() } } : o);
  return { ...r, lhs: norm(r.lhs), rhs: norm(r.rhs) };
}

export const leaf = (r: Rule) => hashJson(normalize(r));

// Sorted-pair keccak tree, the layout OpenZeppelin's MerkleProof verifies.
export function merkleRoot(leaves: Hex[]): Hex {
  if (leaves.length === 0) return `0x${"00".repeat(32)}`;
  let level = [...leaves].sort();
  while (level.length > 1) {
    const next: Hex[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i]!;
      const b = level[i + 1];
      if (!b) {
        next.push(a);
        continue;
      }
      const [x, y] = a < b ? [a, b] : [b, a];
      next.push(keccak256(`0x${x.slice(2)}${y.slice(2)}`));
    }
    level = next;
  }
  return level[0]!;
}

export const invariantsRoot = (rules: Rule[]) => merkleRoot(rules.map(leaf));

function parseFn(fn: string): AbiFunction {
  const item = parseAbiItem(fn.startsWith("function ") ? fn : `function ${fn}`) as AbiFunction;
  if (item.type !== "function" || item.outputs.length !== 1) throw new Error(`rule call must return one value: ${fn}`);
  return item;
}

function coerceArg(type: string, raw: string): unknown {
  if (type.startsWith("uint") || type.startsWith("int")) return BigInt(raw);
  if (type === "bool") return raw === "true";
  return raw;
}

function toBig(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "boolean") return value ? 1n : 0n;
  if (typeof value === "string" && value.startsWith("0x")) return BigInt(value);
  if (typeof value === "number") return BigInt(value);
  throw new Error(`unsupported rule value ${String(value)}`);
}

export async function readOperand(client: PublicClient, o: Operand, blockNumber?: bigint): Promise<string> {
  if ("const" in o) return o.const;
  const fn = parseFn(o.call.fn);
  const args = fn.inputs.map((input, i) => coerceArg(input.type, o.call.args[i] ?? ""));
  try {
    const data = encodeFunctionData({ abi: [fn], args });
    const res = await client.call({ to: o.call.target as Address, data, blockNumber });
    const out = decodeFunctionResult({ abi: [fn], data: res.data ?? "0x" });
    return toBig(Array.isArray(out) ? out[0] : out).toString();
  } catch {
    return "revert";
  }
}

const compare = (a: bigint, op: Rule["op"], b: bigint) =>
  op === "==" ? a === b : op === "!=" ? a !== b : op === ">=" ? a >= b : op === "<=" ? a <= b : op === ">" ? a > b : a < b;

export async function evaluate(client: PublicClient, rules: Rule[], blockNumber?: bigint): Promise<Evaluation[]> {
  const out: Evaluation[] = [];
  for (const r of rules) {
    const [lhs, rhs] = await Promise.all([readOperand(client, r.lhs, blockNumber), readOperand(client, r.rhs, blockNumber)]);
    const holds = lhs !== "revert" && rhs !== "revert" && compare(BigInt(lhs), r.op, BigInt(rhs));
    out.push({ id: r.id, holds, lhs, rhs });
  }
  return out;
}
