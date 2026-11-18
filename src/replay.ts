import { erc20Abi, parseAbi, type Address, type Hex } from "viem";
import { ATTACKER_ETH, bundle as bundleSchema, bundleHash, type Bundle } from "./bundle";
import { evaluate, hashJson, type Evaluation, type Rule } from "./rules";
import type { Fork } from "./anvil";

export type TxResult = { status: "success" | "reverted"; gasUsed: string; created: string | null };
export type Balance = { token: string; before: string; after: string };

export type Measurement = {
  bundleHash: Hex;
  attackerFresh: boolean;
  privileged: boolean;
  txs: TxResult[];
  rules: { id: string; before: Evaluation; after: Evaluation }[];
  balances: Balance[];
  confirmed: boolean;
  reason: string;
};

const controlAbi = parseAbi([
  "function owner() view returns (address)",
  "function admin() view returns (address)",
  "function hasRole(bytes32,address) view returns (bool)",
]);

async function controls(fork: Fork, target: Address, who: Address) {
  const probes = [
    { functionName: "owner" as const, args: [] as const },
    { functionName: "admin" as const, args: [] as const },
    { functionName: "hasRole" as const, args: [`0x${"00".repeat(32)}`, who] as const },
  ];
  for (const p of probes) {
    try {
      const out = await fork.pub.readContract({ address: target, abi: controlAbi, functionName: p.functionName, args: p.args as never });
      if (out === true || (typeof out === "string" && out.toLowerCase() === who)) return true;
    } catch {}
  }
  return false;
}

async function balanceOf(fork: Fork, token: string, who: Address) {
  if (token === "eth") return (await fork.pub.getBalance({ address: who })).toString();
  try {
    return (await fork.pub.readContract({ address: token as Address, abi: erc20Abi, functionName: "balanceOf", args: [who] })).toString();
  } catch {
    return "0";
  }
}

// Replays a bundle on a fork that is still at its pinned block. The fork is consumed: callers
// that need to try again start a new fork (or revert to a snapshot) so every replay begins clean.
export async function replay(fork: Fork, raw: Bundle, rules: Rule[], watchTokens: string[] = []): Promise<Measurement> {
  const b = bundleSchema.parse(raw);
  const hash = bundleHash(b);
  const attacker = b.attacker as Address;
  const pinned = BigInt(b.forkBlock);

  const [nonce, code] = await Promise.all([
    fork.pub.getTransactionCount({ address: attacker, blockNumber: pinned }),
    fork.pub.getCode({ address: attacker, blockNumber: pinned }),
  ]);
  const attackerFresh = nonce === 0 && (!code || code === "0x");
  const privileged = await controls(fork, b.target as Address, attacker);

  const tokens = [...new Set(["eth", ...watchTokens.map((t) => t.toLowerCase()), ...(b.claim.kind === "balance" ? [b.claim.token] : [])])];

  await fork.test.setBalance({ address: attacker, value: ATTACKER_ETH });
  const before = await evaluate(fork.pub, rules);
  const balancesBefore = await Promise.all(tokens.map((t) => balanceOf(fork, t, attacker)));

  const pinnedBlock = await fork.pub.getBlock({ blockNumber: pinned });
  await fork.test.setNextBlockTimestamp({ timestamp: pinnedBlock.timestamp + 1n });
  await fork.test.setBlockTimestampInterval({ interval: 1 });
  await fork.test.impersonateAccount({ address: attacker });

  const txs: TxResult[] = [];
  for (const c of b.calls) {
    const hashTx = await fork.test.request({
      method: "eth_sendTransaction" as never,
      params: [{ from: attacker, to: c.to, data: c.create ?? c.data, value: `0x${BigInt(c.value).toString(16)}`, gas: "0x1c9c380", gasPrice: "0x0" }] as never,
    }) as Hex;
    const receipt = await fork.pub.waitForTransactionReceipt({ hash: hashTx, pollingInterval: 50 });
    txs.push({ status: receipt.status, gasUsed: receipt.gasUsed.toString(), created: receipt.contractAddress?.toLowerCase() ?? null });
  }
  await fork.test.stopImpersonatingAccount({ address: attacker });

  const after = await evaluate(fork.pub, rules);
  const balancesAfter = await Promise.all(tokens.map((t) => balanceOf(fork, t, attacker)));
  const balances = tokens.map((token, i) => ({ token, before: balancesBefore[i]!, after: balancesAfter[i]! }));

  const ruleDeltas = rules.map((r, i) => ({ id: r.id, before: before[i]!, after: after[i]! }));
  let confirmed = false;
  let reason: string;
  if (!attackerFresh) reason = "attacker account is not fresh at the pinned block";
  else if (privileged) reason = "attacker holds a privileged role on the target";
  else if (b.claim.kind === "invariant") {
    const id = b.claim.invariantId;
    const r = ruleDeltas.find((d) => d.id === id);
    if (!r) reason = `claimed rule ${id} is not declared for this target`;
    else if (!r.before.holds) reason = `rule ${id} was already broken before the bundle ran`;
    else if (r.after.holds) reason = `rule ${id} still holds after the bundle`;
    else {
      confirmed = true;
      reason = `rule ${id} broken`;
    }
  } else {
    const token = b.claim.token;
    const bal = balances.find((x) => x.token === token)!;
    confirmed = BigInt(bal.after) > BigInt(bal.before);
    reason = confirmed ? `attacker balance of ${token} increased` : `attacker balance of ${token} did not increase`;
  }

  return { bundleHash: hash, attackerFresh, privileged, txs, rules: ruleDeltas, balances, confirmed, reason };
}

export const resultHash = (m: Measurement) => hashJson(m);

