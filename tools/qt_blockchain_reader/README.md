# Gapcoin Qt Blockchain Reader (Add-on Prototype)

This is a standalone Qt GUI blockchain reader intended as a future add-on for the Gapcoin wallet UI.

## What it includes (MVP)

- Node connection via JSON-RPC (URL + optional user/pass)
- Live mode polling enabled by default: chain tip/peers refresh automatically (Connect needed only after changing endpoint/auth)
- Live mode ON/OFF toggle in the connection bar
- RPC auth fallback without manual credentials:
	- `~/.gapcoin/gapcoin.conf` (`rpcuser` / `rpcpassword`)
	- `~/.gapcoin/.cookie`
- Chain overview (`getblockchaininfo`)
- Mini chart in Chain Overview: Difficulty (x-axis) vs Network Speed / hashrate (y-axis), updated in live mode
	- primary RPC metrics: `getdifficulty` (difficulty) and `getnetworkminingpower` (network speed)
	- compatibility fallback: `getblockchaininfo.difficulty` and `getnetworkhashps`
- Graph mode toggle: `Difficulty vs Hashrate` or `Trend Through Time` (difficulty + hashrate over time)
- Historical backfill: on connect/refresh, chart preloads recent historical samples from chain (`getblock` + `getnetworkhashps`) so graph is visible immediately, then continues in live mode
- Live peers count (from `getnetworkinfo` / fallback `getconnectioncount`) shown in Overview, Block, and Transaction views
- Recent blocks list (`getblockcount`, `getblockhash`, `getblock`) with columns:
	- `height`, `hash`, `shift`, `merit`, `record`, `time`, `tx`
- Block lookup by height or hash (`getblock` with verbosity 2)
- Quick block stepping with `Height -` / `Height +` buttons
- Transaction view supports:
	- txid lookup (`getrawtransaction`, optional blockhash)
	- blockhash-only mode (loads transactions from that block via `getblock <hash> 2`)
- Dedicated `Peers` tab next to `Transaction` with:
	- full peer list from `getpeerinfo` (id, addr, subver, ping, sync state, traffic, ban score)
	- JSON detail view for selected peer
	- manual refresh button plus live updates
- Live records integration from `https://primegaps.cloudygo.com/merits.txt`
	- loaded on Connect
	- auto-refresh every 24h
	- record delta/status shown in `record` column
- Human-readable JSON inspectors for block and tx data

The feature set is based on common blockchain explorer functionality and the Bitcoin-style RPC interface (`getblockchaininfo`, `getblock`, `getrawtransaction`).

## Build

```bash
cd tools/qt_blockchain_reader
cmake -S . -B build
cmake --build build -j
./build/gapcoin-blockchain-reader
```

Requirements:

- Qt6 Widgets + Network (or Qt5 fallback)
- CMake 3.16+

## Porting path into Gapcoin wallet repo

Target wallet repo: `/home/dejan/Git/Gapcoin`

1. Copy this folder into wallet tree (for example `src/qt/addons/blockchain_reader`).
2. Add target sources to wallet GUI CMake (only when `BUILD_GUI=ON`).
3. Replace standalone `main.cpp` with a wallet-integrated panel/widget entrypoint.
4. Wire RPC endpoint/auth from wallet settings instead of local text fields.
5. Register as a new tab in wallet Qt navigation.

## Notes for future versions

- Add mempool page (`getrawmempool`, optional tx decode).
- Add address-centric view if wallet/index layer supports it.
- Add pagination/cache for large block/tx payloads.
- Add dark theme and compact table mode.

## Troubleshooting

- If you get HTTP 401 in the GUI:
	- either enter `rpcuser` / `rpcpassword` manually,
	- or ensure wallet auth files are readable by the app user:
		- `~/.gapcoin/gapcoin.conf` or
		- `~/.gapcoin/.cookie`
- If records cannot be downloaded, the app still works without record badges.
- If tx lookup returns RPC/HTTP 500 for `getrawtransaction`:
	- this usually means `txindex` is disabled on the node,
	- enter the tx's containing `blockhash` in the optional Blockhash field and retry.

## Screenshot

Current UI example:

![Gapcoin Blockchain Reader UI](../../Screenshot%20From%202026-07-03%2019-59-47.png)
