import { createPublicClient, createTestClient, createWalletClient, http, type Abi, type Address, type Hex, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";

// Anvil's published development keys; they only ever sign on local test chains.
export const KEYS = [
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
  "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
  "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
  "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
] as const satisfies readonly Hex[];

export const CHAIN_ID = 4663;

export async function startChain(port?: number) {
  const p = port ?? 20000 + Math.floor(Math.random() * 20000);
  const proc = Bun.spawn(["anvil", "--port", String(p), "--chain-id", String(CHAIN_ID), "--silent", "--host", "127.0.0.1"], { stdout: "ignore", stderr: "ignore" });
  const url = `http://127.0.0.1:${p}`;
  for (let i = 0; i < 100; i++) {
    try {
      const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' });
      if (r.ok) break;
    } catch {}
    await Bun.sleep(50);
  }
  const chain = { id: CHAIN_ID, name: "local", nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [url] } } } as const;
  const transport = http(url);
  const pub = createPublicClient({ chain, transport, pollingInterval: 50 }) as PublicClient;
  const test = createTestClient({ chain, mode: "anvil", transport });
  const wallet = (i: number) => createWalletClient({ chain, transport, pollingInterval: 50, account: privateKeyToAccount(KEYS[i]!) });
  return { url, pub, test, wallet, stop: () => proc.kill() };
}

export type Chain = Awaited<ReturnType<typeof startChain>>;

type Artifact = { abi: Abi; bytecode: { object: Hex } };

export async function artifact(file: string, name: string, root = new URL("../fixtures/out/", import.meta.url)): Promise<Artifact> {
  return Bun.file(new URL(`${file}/${name}.json`, root)).json();
}

export async function deploy(chain: Chain, file: string, name: string, args: unknown[] = [], opts: { from?: number; value?: bigint; root?: URL } = {}) {
  const a = await artifact(file, name, opts.root);
  const w = chain.wallet(opts.from ?? 0);
  const hash = await w.deployContract({ abi: a.abi, bytecode: a.bytecode.object, args: args as never, value: opts.value });
  const receipt = await chain.pub.waitForTransactionReceipt({ hash });
  return { address: receipt.contractAddress!.toLowerCase() as Address, abi: a.abi };
}

export async function send(chain: Chain, from: number, to: Address, abi: Abi, functionName: string, args: unknown[] = [], value?: bigint) {
  const hash = await chain.wallet(from).writeContract({ address: to, abi, functionName, args: args as never, value } as never);
  return chain.pub.waitForTransactionReceipt({ hash });
}
