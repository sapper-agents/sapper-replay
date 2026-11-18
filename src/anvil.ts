import { createPublicClient, createTestClient, http, type PublicClient, type TestClient } from "viem";

export type Fork = {
  url: string;
  block: number;
  // First locally mined block: same state as `block`. Reads and replays start here because some
  // chains (Arbitrum Orbit among them) serve headers without blob fields, which anvil rejects for
  // calls at the forked block itself.
  base: number;
  chainId: number;
  pub: PublicClient;
  test: TestClient<"anvil">;
  stop: () => Promise<void>;
};

async function freePort() {
  const server = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
  const port = server.port;
  server.stop(true);
  return port;
}

async function ready(url: string, proc: Bun.Subprocess, timeoutMs: number) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) throw new Error(`anvil exited with ${proc.exitCode}`);
    try {
      const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }) });
      if (res.ok) return;
    } catch {}
    await Bun.sleep(100);
  }
  throw new Error("anvil did not start in time");
}

// Every fork runs with zero gas price and base fee so ETH balance deltas measure value moved, not gas burned.
export async function fork(opts: { upstream: string; block: number; chainId: number; timeoutMs?: number }): Promise<Fork> {
  const port = await freePort();
  const proc = Bun.spawn(
    [
      process.env.ANVIL_BIN ?? "anvil",
      "--fork-url", opts.upstream,
      "--fork-block-number", String(opts.block),
      "--chain-id", String(opts.chainId),
      "--port", String(port),
      "--host", "127.0.0.1",
      "--gas-price", "0",
      "--base-fee", "0",
      "--disable-min-priority-fee",
      "--no-storage-caching",
      "--silent",
    ],
    { stdout: "ignore", stderr: "pipe" },
  );
  const url = `http://127.0.0.1:${port}`;
  try {
    await ready(url, proc, opts.timeoutMs ?? 30_000);
  } catch (err) {
    proc.kill();
    throw err;
  }
  const transport = http(url, { timeout: 60_000 });
  const chain = { id: opts.chainId, name: "fork", nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [url] } } } as const;
  const pub = createPublicClient({ chain, transport, pollingInterval: 50 }) as PublicClient;
  const test = createTestClient({ chain, mode: "anvil", transport });
  const pinned = await pub.getBlock({ blockNumber: BigInt(opts.block) });
  await test.setNextBlockTimestamp({ timestamp: pinned.timestamp + 1n });
  await test.mine({ blocks: 1 });
  return {
    url,
    block: opts.block,
    base: opts.block + 1,
    chainId: opts.chainId,
    pub,
    test,
    stop: async () => {
      proc.kill();
      await proc.exited;
    },
  };
}

// Methods a lab caller may send to a fork. Anything that could reach a real network or sign is absent.
export const READ_METHODS = new Set([
  "eth_call", "eth_getCode", "eth_getStorageAt", "eth_getBalance", "eth_blockNumber", "eth_getBlockByNumber",
  "eth_estimateGas", "eth_getTransactionReceipt", "eth_getLogs", "eth_chainId", "eth_getTransactionCount",
]);

export function assertForkUrl(url: string) {
  const { hostname } = new URL(url);
  if (hostname !== "127.0.0.1" && hostname !== "localhost") throw new Error(`refusing non-local RPC ${hostname}`);
}
