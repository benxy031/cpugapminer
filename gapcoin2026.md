# GapCoin2026 Wallet Compatibility Guide (Generic)

This document is a general guide for developers who want to adapt their miner for the new GapCoin2026 wallet while keeping compatibility with older (legacy) wallets.

## 1. Problem To Solve

With new wallet implementations, this often happens:

- `submitblock` returns accepted (or a `null` result)
- but the coinbase output is not wallet-owned
- so the reward is not visible in the wallet balance

Because of that, it is not enough for a block to be accepted on-chain. You must also ensure the coinbase output goes to a script the wallet controls.

## 2. Architecture The Miner Should Support

The miner should support two RPC paths:

1. legacy: `getwork` (template + submit)
2. modern: `getblocktemplate` + `submitblock`

Recommendation:

- try `getwork` first (for compatibility with older wallets)
- fall back to GBT+submitblock if `getwork` is unavailable

## 3. Minimal Changes To Add In Any Miner

## 3.1 RPC Mode Detection And Fallback

- add runtime modes: `LEGACY_GETWORK` and `GBT_SUBMITBLOCK`
- automatic fallback `getwork -> gbt`
- clear log message indicating which mode is active

## 3.2 Correct Block Assembly In GBT Mode

For `submitblock`, you must serialize the full block correctly:

- header fields: `version`, `previousblockhash`, `curtime`, `bits`, nonce
- coinbase tx
- merkle root
- tx count varint (CompactSize)
- all other transactions from the template

Most common mistakes:

- incorrect varint length for transaction count
- incorrect byte order when writing the merkle root

## 3.3 Stale Template Protection

If the template changes during scanning, submission must not use mixed old/new data.

Best practice:

- track sequence/template-id per pass
- at submit time, verify the candidate belongs to the same pass
- reject stale candidates before assemble/submit

## 3.4 Wallet-Owned Coinbase Override (Critical)

Add an option such as:

- `--coinbase-script-hex <scriptPubKeyHex>`

Behavior:

- in GBT mode, when this option is set, the miner should assemble the coinbase output using that script
- do not rely on the default template coinbase script if your goal is guaranteed wallet-owned output

Input validation:

- hex format
- even number of characters
- reasonable maximum length

## 3.5 User Warning

If GBT+submitblock is active and payout script is not explicitly set, print a warning that an accepted block may be wallet-invisible.

## 4. What Must Not Break

## 4.1 Legacy getwork

- the legacy flow must remain untouched
- coinbase override typically does not apply to the getwork path

## 4.2 Stratum

- in stratum setups, payout is controlled by the pool
- local coinbase override is not the primary mechanism for pool payout

## 5. Operational Workflow For Users

## 5.1 How Users Obtain scriptPubKey

From wallet RPC (depends on implementation):

- `getaddressinfo <address>` or
- `validateaddress <address>`

Use the `scriptPubKey` field.

## 5.2 How To Start The Miner

Instruct users to pass that script through the coinbase override flag, together with standard mining options.

## 5.3 How To Confirm It Works

After an accepted block, verify:

1. `getblock <hash> 2`
   - coinbase `vout[0].scriptPubKey.hex` must match the script provided to the miner
2. wallet balance (`mine.immature` or equivalent)
   - it should increase
3. `gettransaction <coinbase_txid>`
   - the transaction must be wallet-owned

## 6. Test Plan For Dev Teams

Cover at least these 4 scenarios:

1. Legacy wallet + getwork
2. GapCoin2026 wallet + GBT without coinbase override (expected: possible wallet-invisible reward)
3. GapCoin2026 wallet + GBT with coinbase override (expected: wallet-owned reward)
4. Stratum mode (no regressions)

## 7. UX And Documentation (Mandatory)

Your miner documentation should clearly state:

- what `--coinbase-script-hex` does
- that it is intended for GBT+submitblock wallets
- that legacy getwork remains supported
- short workflow: address -> `getaddressinfo` -> `scriptPubKey` -> miner flag

## 8. Conclusion

For GapCoin2026 compatibility, the key points are:

- dual RPC support (legacy + modern)
- correct full-block assembly in GBT mode
- explicit wallet-owned coinbase script override

Without the third item, you may have a technically accepted block that the user does not see as their reward.

## 9. Submitblock Code Flow (English Example)

Use the following implementation flow in any miner that supports GBT.

### 9.1 High-Level Steps

1. Fetch a fresh template with `getblocktemplate`.
2. Build coinbase transaction:
   - if `coinbase-script-hex` is provided, use it for `vout[0].scriptPubKey`
   - otherwise use wallet/template default behavior
3. Build merkle root from coinbase + template transactions.
4. Build block header (`version`, `prevhash`, `merkleroot`, `time`, `bits`, `nonce`).
5. Serialize full block in consensus format:
   - header
   - CompactSize tx count
   - coinbase tx
   - remaining transactions
6. Hex-encode full block bytes.
7. Submit via `submitblock`.
8. Handle result:
   - `null` (or empty string on some nodes) usually means accepted
   - non-empty string means rejected with reason (e.g. `bad-txnmrklroot`)

### 9.2 Pseudocode

```text
template = rpc("getblocktemplate", [{"rules": ["segwit"]}])

coinbase_tx = build_coinbase_tx(
   height = template.height,
   coinbase_value = template.coinbasevalue,
   payout_script = cli.coinbase_script_hex  # optional override
)

tx_list = [coinbase_tx] + template.transactions
merkle_root = compute_merkle_root(tx_list)

header = build_header(
   version = template.version,
   prev_hash = template.previousblockhash,
   merkle_root = merkle_root,
   ntime = template.curtime,
   nbits = template.bits,
   nonce = found_nonce
)

block_bytes = serialize_block(header, tx_list)
block_hex = hex_encode(block_bytes)

submit_result = rpc("submitblock", [block_hex])

if submit_result is null or submit_result == "":
   log("submitblock accepted")
else:
   log_error("submitblock rejected: " + submit_result)
```

### 9.3 Common Validation Checks Before Submit

- verify tx count encoding is CompactSize, not fixed-width integer
- verify merkle root byte order in header serialization
- verify coinbase output script equals configured payout script (when override is enabled)
- verify candidate still matches active template/pass id (stale protection)

## 10. Real-World Validation Snapshot

The following production-style behavior was observed in live mining after applying the compatibility fixes:

- qualifying gap found and submitted in GBT mode
- RPC response: `{"result":null,"error":null,...}`
- miner log: `submitblock: ACCEPTED (result=null)`
- async submit status moved to `ACCEPTED`
- node advanced to a new tip immediately after submission (`NEW BLOCK ... mining on top`)
- stats reflected `accepted=1`

Interpretation:

- `result=null` with `error=null` is accepted for this wallet RPC
- block payload format is valid for `submitblock`
- end-to-end flow (candidate -> block assembly -> submit -> chain tip update) is working

## 11. CRT Path And nAdd Explained

This section explains the most common source of integration mistakes in high-shift mining.

### 11.1 What CRT Path Means

In CRT-based mining, the miner does not test random candidates one-by-one.
It uses a residue system to skip values that are guaranteed composite, then only
tests survivors. This makes high-shift search practical.

Conceptually, each tested candidate is still a number of the form:

$$
N = (H \ll nShift) + nAdd
$$

where:

- $H$ is derived from the block header hash context
- $nShift$ is the shift parameter (for example, 705)
- $nAdd$ is the additive offset that selects the exact candidate inside that shift space

### 11.2 What nAdd Is (And What It Is Not)

- `nAdd` is not a cosmetic metadata field; it is part of PoW candidate construction.
- changing `nAdd` changes the integer being tested for primality and gap quality.
- at higher shifts, `nAdd` is often much larger than 64-bit and must be handled as a big integer.

### 11.3 Serialization Requirement In submitblock Mode

For modern GBT submit path, full block assembly must preserve the exact `nAdd`
value found by the solver.

Practical rule:

1. serialize `nAdd` as little-endian byte array (minimal representation)
2. prefix it with CompactSize length
3. include it in the variable-length header portion exactly as consensus expects

If this is done incorrectly (wrong endian, truncated to 64-bit, wrong length),
the node typically returns decode/validation errors during `submitblock`.

### 11.4 Difference Between Legacy getwork And GBT submitblock

- legacy `getwork` submit path usually sends a compact payload format specific to that RPC workflow
- GBT `submitblock` requires a full serialized block

Do not reuse legacy payload construction inside GBT `submitblock` path.
That mismatch is a common cause of `Block decode failed`.

### 11.5 Minimal Developer Checklist For CRT + nAdd

- keep `nAdd` as big integer through the whole pipeline
- avoid downcasting `nAdd` to `uint64_t` in assembly code
- ensure `nShift` in submitted block matches the solver context
- use stale-pass/template guards so `nAdd` is submitted with the correct header context
- log header size and serialized block length in debug mode for forensic checks
