import { encodeAbiParameters, keccak256, type Address, type Hex } from "viem";

// Matches SapperCheckerNet.commitmentOf, so a vote can be prepared and checked off chain.
export const commitmentOf = (findingId: Hex, checker: Address, passed: boolean, resultHash: Hex, salt: Hex) =>
  keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "address" }, { type: "bool" }, { type: "bytes32" }, { type: "bytes32" }], [findingId, checker, passed, resultHash, salt]));
