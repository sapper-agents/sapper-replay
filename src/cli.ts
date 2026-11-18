#!/usr/bin/env bun
import { parseArgs } from "node:util";
import type { Address, Hex } from "viem";
import { bundle as bundleSchema } from "./bundle";
import { invariantsRoot, rule } from "./rules";
import { fork } from "./anvil";
import { replay, resultHash } from "./replay";
import { commitmentOf } from "./commitment";

const usage = `sapper-replay: replay a Sapper reproduction bundle on a fork and print the measured result.

Usage
  sapper-replay replay --bundle bundle.json --rules rules.json --rpc <archive rpc url> [--tokens 0x..,0x..]
                       [--finding 0x.. --checker 0x.. --salt 0x..]
  sapper-replay root --rules rules.json

The replay forks the chain at the bundle's pinned block, so the RPC must serve historical state for it.`;

const { values, positionals } = parseArgs({
  args: Bun.argv.slice(2),
  allowPositionals: true,
  options: { bundle: { type: "string" }, rules: { type: "string" }, rpc: { type: "string" }, tokens: { type: "string" }, finding: { type: "string" }, checker: { type: "string" }, salt: { type: "string" }, help: { type: "boolean", short: "h" } },
});

const readRules = async (path?: string) => (path ? rule.array().parse(await Bun.file(path).json()) : []);
const command = positionals[0];

if (values.help || !command) {
  console.log(usage);
  process.exit(command ? 0 : 1);
}

if (command === "root") {
  console.log(invariantsRoot(await readRules(values.rules)));
  process.exit(0);
}

if (command !== "replay" || !values.bundle || !values.rpc) {
  console.error(usage);
  process.exit(1);
}

const b = bundleSchema.parse(await Bun.file(values.bundle).json());
const rules = await readRules(values.rules);
const lab = await fork({ upstream: values.rpc, block: b.forkBlock, chainId: b.chainId });
try {
  const m = await replay(lab, b, rules, values.tokens?.split(",").filter(Boolean) ?? []);
  const hash = resultHash(m);
  const vote = values.finding && values.checker && values.salt ? commitmentOf(values.finding as Hex, values.checker.toLowerCase() as Address, m.confirmed, hash, values.salt as Hex) : undefined;
  console.log(JSON.stringify({ confirmed: m.confirmed, reason: m.reason, resultHash: hash, commitment: vote, measurement: m }, null, 2));
  process.exitCode = m.confirmed ? 0 : 2;
} finally {
  await lab.stop();
}
