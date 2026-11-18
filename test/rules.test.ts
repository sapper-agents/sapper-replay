import { expect, test } from "bun:test";
import { invariantsRoot, leaf, merkleRoot, type Rule } from "../src/rules";
import { receiptHash, verifyChain, ZERO, type ReceiptBody } from "../src/receipts";
import { commitmentOf } from "../src/commitment";

const rule = (id: string, extra: Partial<Rule> = {}): Rule => ({ id, description: `rule ${id}`, lhs: { const: "1" }, op: "==", rhs: { const: "1" }, ...extra });

test("the rules root ignores order and address case", () => {
  const a = rule("a", { lhs: { call: { target: "0xAbCdEf0000000000000000000000000000000001", fn: "x() view returns (uint256)", args: [] } } });
  const lower = rule("a", { lhs: { call: { target: "0xabcdef0000000000000000000000000000000001", fn: "x() view returns (uint256)", args: [] } } });
  expect(invariantsRoot([a, rule("b")])).toBe(invariantsRoot([rule("b"), lower]));
  expect(invariantsRoot([a])).toBe(leaf(a));
  expect(merkleRoot([])).toBe(ZERO);
});

test("a receipt chain detects any edited step", () => {
  const steps: (ReceiptBody & { hash: `0x${string}` })[] = [];
  let prev = ZERO;
  for (let i = 0; i < 3; i++) {
    const body: ReceiptBody = { jobId: "j", findingId: null, step: i, role: "breaker", agent: "0x1", action: "step", prevHash: prev, inputHash: ZERO, modelId: "", toolCallsHash: ZERO, costMicros: i, outputHash: ZERO };
    const hash = receiptHash(body);
    steps.push({ ...body, hash });
    prev = hash;
  }
  expect(verifyChain(steps)).toBe(true);
  steps[1]!.costMicros = 99;
  expect(verifyChain(steps)).toBe(false);
});

test("commitments bind the checker, the vote and the salt", () => {
  const f = `0x${"ab".repeat(32)}` as const, r = `0x${"cd".repeat(32)}` as const, s = `0x${"ef".repeat(32)}` as const;
  const c = "0x00000000000000000000000000000000000000c1" as const;
  expect(commitmentOf(f, c, true, r, s)).not.toBe(commitmentOf(f, c, false, r, s));
  expect(commitmentOf(f, c, true, r, s)).not.toBe(commitmentOf(f, "0x00000000000000000000000000000000000000c2", true, r, s));
});
