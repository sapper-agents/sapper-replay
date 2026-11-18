import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type { Address } from "viem";
import type { Bundle } from "../src/bundle";
import { fork } from "../src/anvil";
import { replay, resultHash } from "../src/replay";
import { seed, type Scenario } from "./scenarios";
import { CHAIN_ID, KEYS, startChain, type Chain } from "./chain";

let chain: Chain;
let scenarios: Scenario[];
let block: number;

beforeAll(async () => {
  chain = await startChain();
  scenarios = await seed(chain);
  block = Number(await chain.pub.getBlockNumber());
}, 60_000);
afterAll(() => chain.stop());

const fresh = () => privateKeyToAccount(generatePrivateKey()).address.toLowerCase() as Address;

async function run(s: Scenario, attacker: Address, calls?: Bundle["calls"]) {
  const b: Bundle = { version: 1, chainId: CHAIN_ID, target: s.target, forkBlock: block, attacker, calls: calls ?? (await s.exploit(attacker)), claim: s.claim as Bundle["claim"] };
  const f = await fork({ upstream: chain.url, block, chainId: CHAIN_ID });
  try {
    return await replay(f, b, s.rules, s.watchTokens);
  } finally {
    await f.stop();
  }
}

describe("seeded bugs", () => {
  test("ten fixtures are seeded", () => expect(scenarios.length).toBe(10));

  test("every seeded exploit reproduces from a fresh account", async () => {
    const results = [];
    for (const s of scenarios) {
      const m = await run(s, fresh());
      results.push({ name: s.name, confirmed: m.confirmed, reason: m.reason });
    }
    const confirmed = results.filter((r) => r.confirmed);
    if (confirmed.length < 10) console.table(results);
    expect(confirmed.length).toBe(10);
  }, 120_000);

  test("replay is deterministic across fresh forks", async () => {
    const s = scenarios[3]!;
    const attacker = fresh();
    const calls = await s.exploit(attacker);
    const [a, b] = [await run(s, attacker, calls), await run(s, attacker, calls)];
    expect(resultHash(a)).toBe(resultHash(b));
  }, 60_000);

  test("a privileged or used account cannot confirm", async () => {
    const owner = privateKeyToAccount(KEYS[0]).address.toLowerCase() as Address;
    const s = scenarios.find((x) => x.name === "upgrade drops owner check")!;
    const m = await run(s, owner);
    expect(m.confirmed).toBe(false);
    expect(m.attackerFresh).toBe(false);
  }, 30_000);

  test("a bundle that breaks nothing does not confirm", async () => {
    const s = scenarios.find((x) => x.name === "redeem without burn")!;
    const m = await run(s, fresh(), [{ to: s.target, data: "0x", value: "0" }]);
    expect(m.confirmed).toBe(false);
  }, 30_000);
});
