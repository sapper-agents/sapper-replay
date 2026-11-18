import { keccak256, toBytes, type Hex } from "viem";
import { canonicalJson, merkleRoot } from "./rules";

export type ReceiptBody = {
  jobId: string;
  findingId: string | null;
  step: number;
  role: string;
  agent: string;
  action: string;
  prevHash: Hex;
  inputHash: Hex;
  modelId: string;
  toolCallsHash: Hex;
  costMicros: number;
  outputHash: Hex;
};

export const ZERO = `0x${"00".repeat(32)}` as Hex;

export const receiptHash = (r: ReceiptBody) => keccak256(toBytes(canonicalJson(r)));

export const hashText = (s: string) => keccak256(toBytes(s));

export function verifyChain(chain: (ReceiptBody & { hash: Hex })[]) {
  let prev = ZERO;
  for (const [i, { hash, ...body }] of chain.entries()) {
    if (body.step !== i || body.prevHash !== prev || receiptHash(body) !== hash) return false;
    prev = hash;
  }
  return true;
}

export const receiptsRoot = (hashes: Hex[]) => merkleRoot(hashes);
