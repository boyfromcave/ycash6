# Yugen on the ycash6 line: design notes

## Decision N-D1: proofs verified by a helper process, not linked into ycashd
Options: (a) link yugen-ref + both proof crates into src/rust (cxx); (b) a separate binary run per
transaction. Chosen (b), `contrib/yugen-leafverify`. Reasons: the proof crates need Rust 1.98.1
(ycash6 pins 1.96.0); proof-a's vendored leanMultisig and proof-b2's Binius64 bring their own
workspaces and lock files that would enter ycashd's offline vendored build; the helper uses the
wallet's exact pins and verifier setup (Y-W3) so both sides cannot drift. Costs: a process start
and verifier setup per transaction (results cached by request hash, so mempool -> template ->
block verifies once); the note-tree root also comes from the helper (`root`). Reverse when the
verifier crates build on the node's toolchain inside its vendored set (then call through cxx).

## Decision N-D2: pool state in memory, rebuilt from blocks (superseded by M-3 below)
The state (tree, nullifiers, roots per block) is rebuilt from the active chain whenever its tip is
not the parent of the block being connected; this covers restart and reorganisation with no undo
records. Proofs are not re-verified on a rebuild. Adequate for devnets; N-4's persistent undo
data, turnstile and pool balance are open.

## Decision N-D3: proofs inline for M1
Proofs travel in the Yugen field and count to block bytes (stricter than spec §16.2, which
excludes them from the 2,000,000). One leaf (≤ 1,556,000 bytes) fits a block. Sidecar in M2
(pool agent's wire form accepted for then). The txid covers the proofs (v4 rule), so a proof is
malleable into a new txid until the sidecar; recorded as open.

## Decision N-D4: the bundle transaction and the proof sidecar (M2)
A bundle transaction is the Yugen group with the §15.1 encoding in the `transfer` field and both
inline proof fields empty (a leaf always has both). Options for the proofs: (a) inline, as leaves;
(b) sidecar after the block's transactions, yolo's `proof_section` form. Chosen (b),
the spec's form (§15.1: re-proving changes the txid only through the committed hashes). Network and
RPC streams carry the sidecar (`CBlock::vYugenProofs`, read only from a CDataStream with bytes left);
block files do not: the sidecar is saved at receipt as `<datadir>/yugen/proofs/blk-<hash>.bin` and
mempool bundles' proofs as `<txid>.bin`; `ReadBlockFromDisk` re-attaches them. A missing, malformed
or substituted proof (hash mismatch) is `BodyCorruption::Possible`, never a verdict on the block.
Leaves keep their proofs inline (N-D3). Reverse when peer messages for proofs (Appendix B) land.

## Decision N-D5: M2 scope of the bundle rules
Built: B0 (no frozen/pause/halt state exists yet), B1 (helper, yugen-ref `Bundle::decode`), B2
(roots, registry root, block hash), B3/B4 (helper, yugen-ref functions with the network's
activation height; yugen-ref's `resolve_anchor` fixes ACTIVATION_HEIGHT 4096), B5 (System A in the
helper as bundler-verify's SystemA; System B through `b2verify root` at yugen-proof-b2 3e7a5d0, proof B
wire = `LE32(n) || n LE64 public words || proof`, rate 2, kind t/t0, digest = bstmt), B6 S1 skips,
B7, B8 pay (yugen-ref `bundle_pay`), record run checked as the coinbase's last outputs, W1, W3, W5
with the run term; since spec 0.5.4 the VB records (N-D10: B1's record rules, B1a, B6 S2, deposit
coins and scripts, record outputs, sigops, B9), B6's failure of a bundle with a withdrawal above the
window's gross cap `K` and S3 (the value cap), and for a leaf the same two rules (N-D11). Not built
(bundles refused or not modelled): the classification of a withdrawal as immediate, maturing or queued
(§13.3.5: `τ`, `Ks`, `G`, `I`, maturity `M`, the queue; a withdrawal's outputs are immediate, for a
leaf and a bundle alike, see "Known issues for beta4"), the fee outflow scaling p/x of the run
(§13.3.5), turnstile (review H-3), peer relay of bundle proofs.
Test-only: `-yugenteststubproofs` (regtest only, refused elsewhere) accepts stub proofs that bind
`bstmt`; the helper's `testbundle` builds bundles of random transfers with them. Real bundle proofs are
not yet run through the node in its tests: System B root verification needs a 9.6 GB memory footprint,
and no real bundle proved over a regtest anchor exists yet.

## Decision N-D6: the turnstile B, seeded at 0 (review H-3; spec 0.5.2 §7.9 rule 4, §13.3.2)
`PoolState::balance` is B. Each applied leaf or bundled transfer debits `vb + fee`
(`Transfer::TransparentDelta`; = minus `vb_in - vb_out - fee`); a skipped bundled transfer moves
nothing. A block (or mempool candidate) that takes B below 0, or above MAX_MONEY, at any
transaction is `bad-yugen-turnstile` (DoS 100). The miner keeps a running debit and skips a
transaction the pool cannot cover; `StaleInPool` evicts one after a reorganisation lowers B.
Exposed as `yugen_getinfo.pool_balance[_zat]`, `yugen_getblockdata.pool_balance_{before,after}_zat`
and a `yugen` entry appended to `valuePools` in `getblockchaininfo` and `getblock` (after orchard,
only where Yugen has a height), so Sapling -> transparent -> Yugen flows are auditable pool by pool.
Options: (a) seed B = CANARY_VALUE as §13.3.2 says; (b) seed B = 0 until the funded canary exists.
Taken: (b). The funded canary note and its funding (§13.2, §13.3.4) are not built on this line:
cm* is a constant leaf 0 with no value behind it, so (a) would let `CANARY_VALUE` be withdrawn
that no deposit backs. With (b) withdrawals are bounded by deposits, Theorem V' holds with the
canary term 0. Reverse when §13.2's funded canary lands: the activation block credits its
funding to B in the same change.
Status: accepted (2026-11-24).

## Decision N-D7: the txid does not cover the leaf proofs (review M-4)
The spec is silent on the leaf txid. Options: (a) txid over the serialization with the proofs
replaced by their hashes (the review's text); (b) txid over the serialization with both proof
fields empty, auth digest the proofs' hash; (c) as (b), auth digest left at the pre-NU5
placeholder. (a) still changes with a re-randomised proof. (b) breaks relay: v4 inventory is
MSG_TX, whose `hashAux` is the placeholder, and getdata matches it against the auth digest.
Taken: (c). The txid now covers exactly what the signature hash covers (ZIP-243 + hashYugen over
the transfer bytes). Consequences, handled: a block's leaf proofs are no longer pinned by
`hashMerkleRoot`, so every proof-derived refusal (`bad-yugen-proof`, `-proof-missing`,
`-proof-too-long`, `-leaf-weight`) is `BodyCorruption::Possible` (the block is not marked invalid
for good; a body with valid proofs can still be accepted), as the bundle sidecar already is; a
Yugen tx refused with corruption possible is not put in `recentRejects`, so a bad-proof copy
cannot keep the valid one out. A bundle (proofs empty) hashes as before. Only regtest has a
Yugen height, so only regtest sees the change. Open for the wallet: yewd-yugen's fallback
`Tx::txid()` (yew `yewd/yugen/wallet/src/tx.rs`) hashes the proofs; it is used only when the node
returns no txid. Reverse if the spec defines a leaf txid or an auth-data commitment.
Status: accepted for regtest (2026-11-24); proposed for spec 0.5.3 in
`doc/yugen-spec-proposal-0.5.3-txid.md`.

## Decision N-D8: the kind of a Yugen transaction is read from committed bytes (independent review)
N-D4 told a bundle from a leaf by its proof fields being empty, and N-D7 put those fields outside the
txid, so a relay could empty a leaf's proofs (or add one to a bundle) and have the node judge the
honest txid as the other kind: a refusal with DoS 100 and no `BodyCorruption::Possible`, the block
marked `BLOCK_FAILED_VALID` (a chain split against a node that saw the honest copy), and the shared
wtxid put in `recentRejects` (the honest copy censored). The spec does not mark the kind: §15.1
defines the bundle field and §7.1 the transfer, and a leaf of fee class 0 begins with `0x00` like a
bundle's version byte (spec vector `transfer.json` 0 does), so the first byte is no marker.
Options: (a) a bundle iff `transfer[0] = 0x00` (misreads every fee-class-0 leaf); (b) a leaf iff the
bytes decode under §7.1 with `LEAFFEE` (an honest bundle of a leaf's exact length and suitable
slot/root bytes reads as a leaf, about one in 10^5); (c) a new version group for bundles (a new
transaction format); (d) a bundle iff the bytes parse as §15.1 through the tree and the record
lengths (a leaf's nullifier and commitment bytes would have to form a valid tree and exact length:
at most 3.98e-10, about 2^-31.2, per fee-class-0 leaf, 0 without a package, computed exactly in
`doc/yugen-spec-proposal-0.5.3-envelope-kind.md` by `qa/yugen/kind_misread_rate.py`, not "far
below 2^-30"); (e) an explicit marker in the spec. Taken at
first: (d), no format change. **Since spec 0.5.3 (lead architect, 2026-11-25): (e).** §15.1 sets
`bundle_version` = `0x80`; a Yugen field whose first byte is `0x80` is a bundle and any other a leaf
(whose first byte is `fee_class`, at most 3), so `yugen::IsBundleEncoding` is `b[0] == 0x80` and
`DecodeBundleTransfers` refuses any other version. The heuristic and its misread rate are gone: no
honest leaf can be read as a bundle, and kogany needs only the byte test. With it: a bundle with
an inline proof is `bad-yugen-bundle-inline-proofs` and a leaf without its proofs
`bad-yugen-proof-missing`, both `BodyCorruption::Possible`; `bad-yugen-block-weight` (it counts leaf
proofs and the sidecar) is `Possible` too. The mempool was not exposed on this line: a mempool
`CValidationState` has no merkle root checked, so `BodyCorruption::Default` is corruption-possible
there (`consensus/validation.h`) and the N-D7 gate already kept every Yugen refusal out of
`recentRejects`; the orphan path's unconditional insert is unreachable for a leaf (over the
99,999-byte orphan bound) and for a bundle (no inputs). The sidecar
exists only from `UPGRADE_YUGEN`: earlier, bytes after `vtx` are ignored, as upstream ignores
trailing bytes (since the review of 2026-11-25; before it such a block was refused as a body), and
nothing is saved or re-attached. Every txid is
unchanged. Tests: `qa/rpc-tests/yugen_strip.py`, gtest `Yugen.KindFromCommittedBytes`,
`Yugen.KindOfSpecVectors`, `Yugen.KindMarkerIsFirstByte`. (The 0.5.2-era "reverse if the spec gives
the field an explicit kind" happened: 0.5.3.)
Status: accepted for regtest (2026-11-25); needs review by two people independent of the author.

Relay order: `CompareInvMempoolOrder` announces a Yugen transaction's in-pool ancestors first only
for Yugen transactions and their descendants (`CTxMemPool::YugenRelayDepth`); every other transaction
has key 0 and keeps upstream's order (`CompareDepthAndScore`).

Proof verification under `cs_main` (open, documented, not restructured): a leaf's helper run happens
under `cs_main` in `AcceptToMemoryPool` and in `ConnectBlock`. Exposure reduced, not removed: the
proofs run last, after decode, anchors, nullifiers, inputs and fees; a refused proof scores DoS 100;
and a peer whose Yugen transaction was refused gets no other one judged for 10 s (asked for again by
`AskFor`'s two-minute retry instead). Removing it needs verification outside `cs_main` (a
verification queue with revalidation at admission), a restructuring of `AcceptToMemoryPool` left for
the proof-relay work (Appendix B).

## Review fixes (internal review, 2026-11-24)
H-1: the helper is three-valued (0 accept, 10 reject since the review of 2026-11-25, else
failure); a failure is not a verdict (block not marked invalid; see that review below for what a
connect does with it), DoS 0 in the mempool. M-2: fork/execv, no shell, `-yugenverifytimeout`
(default 600 s, a B root verification is tens of seconds), timeout = failure. The helper still runs
under cs_main: block validation holds it throughout on this code base; releasing it is not a
contained change. M-1: `PreCheckMempoolTx` (decode, anchors, nullifiers) where the old call was;
the helper after the script checks. H-2: `mapYugenNullifiers` in the mempool (admission,
`removeConflicts`), `removeYugenStale` on connect (spent nullifiers, anchors leaving the window)
and disconnect (anchors at or above the disconnected height), miner skips stale Yugen txs. Left
for a follow-up: H-3, M-3, M-4, L-1..L-3, now done on yugen/turnstile:
H-3: N-D6. M-3: each `BlockRecord` carries its undo data (block hash, nullifiers added, commitment
count, B before and after); `yugen::DisconnectBlock` (from `DisconnectBlock`, beside the vault
database) reverses the tip from it; the state is saved to `<datadir>/yugen/state.dat` (checksummed,
atomic rename) at every chainstate flush and loaded once at startup; on a mismatch the state undoes
records back to the active chain and replays only the blocks it lacks; from activation only when
the file is missing or corrupt. `Ensure` never throws: a state fault is `state.Error` in
ConnectBlock (not a verdict), DoS 0 in the mempool. ApplyBlock is all or nothing, and checks
(fJustCheck, mempool, template) apply in place and undo, with no copy of the state. Still open:
the root helper takes the full commitment list (the review's `root-append` frontier), one helper
run per block with commitments. M-4: N-D7. L-1: not reproduced on this line: 6.x `IsStandardTx`
has no transaction size cap (leaf transactions relay without `-acceptnonstdtxn`, yugen_leaf.py);
nothing changed. L-2: the verified-document cache is bounded (50,000, oldest out). L-3:
`bad-yugen-vb-range` in `CheckLeafTransferStructure` when `|vb| + fee > MAX_MONEY`.


## Decision N-D9: a leaf's unsigned fields are fixed (independent review M-1)
§7.3 binds `vout` only through `tout_hash`, which is zero without flag `VB`, and a leaf with no
transparent input carries no signature, so `vin`, `vout`, `nLockTime` and `nExpiryHeight` were
unbound there: a relay could add an output paying itself the fee, or change the lock time, and get
a new txid spending the same nullifiers. Spec 0.5.2 defined the transfer, not the enclosing
transaction; the rule is spec 0.5.3 **§7.9 rule 1a** (the leaf envelope; proposed in
`doc/yugen-spec-proposal-0.5.3-envelope-kind.md`, approved by the lead architect 2026-11-25).
Rule (`yugen::CheckLeafEnvelope`, from
`ContextualCheckTransaction`, DoS 100, a verdict: the fields are committed by the txid): a leaf
without `VB` has no transparent input and no transparent output
(`bad-yugen-leaf-transparent-without-vb`); a leaf with no transparent input has `nLockTime` 0
(`bad-yugen-leaf-locktime`) and `nExpiryHeight = h_a + ANCHOR_WINDOW` for its anchor height at the
block's height (`bad-yugen-leaf-expiry`). It is what the wallet engine writes (yew
`yewd/yugen/wallet/src/tx.rs` and `engine.rs`: lock time 0, `expiry_height(ha)`; deposits carry `vin`
and no `vout`, withdrawals `vout` and no `vin`, shielded sends neither), so no honest transaction
changes. A deposit's other fields are covered by its inputs' signatures. Test: gtest
`Yugen.LeafEnvelopeIsFixed`. Status: needs review by two people independent of the author.

## Decision N-D10: VB records in a bundle (spec 0.5.4 §15.1, §15.5, §15.6)
- Decoding (`DecodeBundleTransfers`, `DecodeRecord`): each record exactly as §15.1, in field order,
  first error wins, with bundle.json's names (`bundle-truncated`, `bundle-vout`, `bundle-vin`,
  `bundle-withdrawal-sum`); canary flags are refused in the same pass. The rest of B1 (payee table,
  tree limits, anchor order and use, `nf*`, mixed schemes) stays in the helper (yugen-ref
  `Bundle::decode`), so the node's own reason matches the spec's error wherever the first failure is
  in a part it decodes (test `Yugen.BundleVectors` lists the cases).
- Where the coins move. Options: (a) in `yugen::ConnectBlock`, after main.cpp's transaction loop;
  (b) in the loop, at the bundle's place. Chosen (b), `ConnectBundleCoins` after `UpdateCoins`: B6
  evaluates each transfer against the state left by every earlier transaction, so a later
  transaction spending a deposited coin must fail and a record output must be spendable later in the
  block; (a) cannot give either. It decides S1 (pool and block nullifiers) and S2 (coin unspent,
  coinbase maturity), checks the coin templates and the balance, spends the inputs and creates the
  outputs at the txid (indices across all records; a skipped record's are null). The script check
  needs the transfer hash, which only the helper computes (§7.3), so it runs in `yugen::ConnectBlock`
  after B5 (`DepositSignatureChecker`: `dep_sighash`, SIGHASH_ALL only, the flags in force plus
  STRICTENC, LOW_S, SIGPUSHONLY, MINIMALDATA, CLEANSTACK); the helper's `bundle` result carries each
  transfer's `transfer_hash`. Reverse if the node gains its own transfer hash.
- Undo (B9): the bundle's `CTxUndo` starts with one entry whose script is `OP_RETURN` and one byte per
  transfer (the applied mask), then the coins spent; `DisconnectBlock` reads the mask to restore
  exactly those inputs and remove exactly those outputs, and a replay of the pool state takes the
  masks from the undo data (a pruned node cannot replay a bundle with a deposit).
- Sigops: `GetLegacySigOpCount` adds the legacy count of every record output script.
- Value pools: the block's transparent value moves by the outputs created less the coins spent.
- Pool policy: a bundle's deposit coins must be confirmed, mature and spent by no pooled
  transaction (a leaf the bundle supersedes excepted) and no other pooled bundle; a transaction that
  spends a coin a pooled bundle deposits is refused (`bad-yugen-bundle-deposit-in-mempool`); a block
  that spends one evicts the bundle (`removeConflicts`, `StaleInPool`). So every template's bundles
  apply in full. A record output of a pooled bundle is not visible to the pool's coins (a child waits
  for the block). Not built: the wallet does not see record outputs or record inputs; the address
  and spent indexes do not index them ("Known issues for beta4", K-3).
- Tests: gtest `Yugen.BundleVectors` (every bundle.json 0.5.4 case the node decides) and
  `Yugen.BundleVbRecordsConnect`; `qa/rpc-tests/yugen_bundle_vb.py` (deposit and withdrawal mined,
  outputs spent, disconnect and reconnect, replay from undo data).

## Decision N-D11: the value cap and the gross cap K (spec 0.5.4 §13.3.5, §13.3.6, §15.6 B6 S3)
`cap(h)` (`RatchetCap`, `ValueCap`) and the window's `K = floor(cap(h_w) × 125 / 1000)` (`GrossCap`,
`h_w` the window's first height) are pure functions of the height (`src/primitives/yugen.h`; no
frozen mode on this line, so `h' = h`). Consensus: a leaf withdrawal above `K` is
`bad-yugen-withdrawal-above-k`; a leaf deposit after which `B > cap(h)` is `bad-yugen-value-cap`; a
bundle with any transfer whose `vb_out > K` is `bad-yugen-bundle-withdrawal-above-k`, skipped or not
(B6 first); a bundled deposit with `B + vb_in − fee > cap(h)` is skipped (S3), `B` as the block's
earlier Yugen transfers left it (`BlockCoins::debited` in `ConnectBundleCoins`; `ApplyBlockInner`
checks that the decision agrees). The pool and the miner refuse a leaf deposit the cap no longer
admits (`StaleInPool`, `CreateNewBlock`); the pool refuses a bundle with a skip
(`bad-yugen-bundle-skips`), S3 included. With `B` seeded at 0 (N-D6) deposits may reach `cap(h)`
itself. Tests: gtest `Yugen.RatchetAndOutflowCapVectors` (safety.json `ratchet` without a freeze and
`outflow-caps`), `Yugen.LeafValueCapAndGrossCap`, `Yugen.BundleVbRecordsConnect` (S3 skip, K failure).

## Decision N-D12: a bundle's VB records never touch what the vault primitive or the YED module tracks (review, 2026-11-25; revised 2026-11-26)
The defect: a bundle's record inputs and outputs (B1a: the bundle transaction has no `vin`/`vout`) are
spent and created in `ConnectBundleCoins`, but the vault primitive (`vault::ApplyBlock`, `IsVaultRelevant`,
`TouchesTemplate`) and the YED module (`ProcessTx`) read `tx.vin`/`tx.vout` only. `DepositScriptOk`
admits P2PKH and TX_PQPKH, exactly where YED tokens sit, so a bundled deposit of a token coin left the
module's `TokenRecord` and `Totals` counting a spent outpoint; and record output scripts were free, so a
V- or I-shaped output (or an act) could be created past the primitive's and the module's creation rules.

Four-part check. The leaf path does X (spends a token coin as an ordinary input: the module reads it,
IN-1, and burns the YED; creates V/I/act outputs in `tx.vout`: the primitive and the module judge them)
in `src/yellowback/state.cpp` `ProcessTxImpl` and `src/vault/state.cpp` using mechanism M (both read the
transaction's own `vin`/`vout`). The bundle path is Z (records outside `vin`/`vout`), which lacks M. So
the adaptation W keeps such coins and outputs out of bundles; they go by a leaf, whose outcome is
unchanged (as `DepositScriptOk`'s "any other coin deposits by a leaf transfer"):
- **Inputs: a skip (S2), never a failure.** A deposit whose coin was created in the bundle's own block,
  or which the module tracks in its state after the parent (a token, a vault, an intent, an attestor
  bond; `YellowbackIndex::TracksAtParent` through `yugen::g_moduleTracks`), is skipped exactly as a
  missing or immature coin: the record is not applied, its coin stays unspent, its fee follows the
  existing skip rules, the undo mask records the decision and a replay reads it from there. A skipped
  record is never checked against the module (§15.5: a skipped deposit is not verified), and the module
  itself never looks at record inputs.
- **Outputs: a failure.** A record output that is an act or V- or I-shaped (`MatchVault`/`MatchIntent`
  not `NONE`, any tag, malformed included) fails the bundle, skipped or not, as B6's `K` does
  (`bad-yugen-bundle-record-output`).
The vault primitive's own coins need no input rule: vaults and intents are templates and bonds are
P2SH, all refused by `DepositScriptOk` already.

Why a skip. The first version (6cf7dc15b) made a tracked record input invalidate the bundle under the
module and claimed that a later transaction could not trigger it. That was false: a coin's token status
is fixed once the coin exists, but a bundle may name a coin that does not exist yet. A holder of a
signed, unbroadcast YED transaction knows its txid; a host bundles a deposit of `(txid, 0)` (harmless
then: an S2 skip), the YED transaction is broadcast, and every node would refuse the whole bundle,
losing its proving work. As a skip, the same sequence only skips that one record (unless every other
transfer of the bundle is skipped too: `bad-yugen-bundle-none-applied`, see the host policy).

Why the parent's state and the same-block skip. The coins move in `ConnectBundleCoins`, inside
main.cpp's transaction loop; the module evaluates the block after it, so its in-order pass cannot
decide a coin's fate in time. Every coin from an earlier block is decided exactly by the module's state
after the parent (a token's status is set when its coin is created; a token spent earlier in the block
is a spent coin, S2 already). Only a coin created in the same block could have become a token at an
earlier position, and the same-block skip covers it without the module's in-block state (stricter than
needed; the pool already takes only confirmed deposit coins). The block connect, the template's and the
pool's dry runs (`CoinsAtTip`, both at the tip) and the replay (the undo mask) therefore decide alike.
The module's answer has three states (review, 2026-11-26): tracked, not tracked, or unknown. It is unknown
when the index is stopped or unhealthy (any storage failure makes it so, the hooks' and also
`MempoolCheck`'s, `AddAttestation`'s and `BuildBundle`'s, after which the node runs on), when it is empty
at or past its start height, or when its tip is not the parent. Unknown is never "not tracked": a block
being connected stops the node with a node failure (`AbortNode`, as `CheckConnect`'s own failure does), so
the block is not marked invalid and connects once the index is rebuilt (`-reindex-yellowback`); the pool
and the template refuse the bundle for the moment. The first version answered "not tracked", so an
unhealthy node applied a deposit the others skip (and never verify) and could mark a valid block
`BLOCK_FAILED_VALID` for good. The one place where unknown is expected is a re-verification of an
active-chain block (`VerifyDB`, `verifychain`, K6): the module's state after its parent is gone, so
`ConnectBlock` reads the block's undo data and `ConnectBundleCoins` takes the module's decision from the
recorded applied mask (a record that every other rule would apply and the mask records skipped was the
module's skip); every other rule is re-decided and checked as before. The hook is set when the module is
known to be live (before `VerifyDB` runs at startup), and one call per bundle asks for all its deposit
coins (one lock, one tip read).

Nodes without an attestor set. Where the module is not live (`g_yellowbackLive` false) the hook is unset
and nothing is tracked, so such a node applies a deposit a live node skips: the two would hold different
coins, a split. It cannot happen on a public network: the attestor set is a chain parameter there
(`ParamsForNetwork`, testnet-yb-fast's `TEST_FAST_ATTESTOR_SET_ID`), so every node of a network is live
or none is, and where none is no coin is ever tracked (a YED vault is created only under the set,
`ValidateCreate`'s `bad-yellowback-vault-set`, so the tracked coins are a function of the set and cannot
be maintained without it). On regtest the set is a node parameter (01/V-7, until P8): nodes started with
and without it already compute different module state and may now also split on a bundle's deposit of a
tracked coin; a regtest network that uses YED and Yugen together must give every node the set
(`yugen_bundle_vb_module.py` uses exactly this difference to build its block).

Why a failure for outputs, and that it is not griefable. Record outputs are bytes the bundle author
writes at build time, and the test is a pure function of the script (no chain state, no height), so no
later transaction can change the verdict; a host checks its own bundles before proving.

Host policy (yugen-bundler, any bundling host): accept only deposit coins that are confirmed and that
the module does not track at the tip (the pool refuses any bundle with a skip,
`bad-yugen-bundle-skips`); a deposit voided later by a YED transaction is then a skip, not a loss of
the bundle. A skip saves the bundle only while one transfer stays applied: a bundle whose every transfer
is a deposit its depositors can turn into skips (a coin they make tracked or spend, or one created in
the bundle's block) still fails as a whole (`bad-yugen-bundle-none-applied`), so the griefing above is
narrowed, not closed. A host does not build a bundle made only of deposits from one untrusted source, and
screens every deposit as confirmed and untracked.

Cost. `TracksAtParent` takes the index lock and reads the tip record once per bundle, then up to four keys
per deposit input, at the bundle's admission to the pool, per block template and at the block's
connection; never on the per-tip pool re-check (`StaleInPool`, `RemoveInvalidVaultSpends`). For a
~53,000-input bundle that is ~212,000 LevelDB reads per evaluation, mostly cached: a known issue for beta4
(one prefix lookup would cut it).

Spec status: both rules are pending a spec proposal for 0.5.5
(`doc/yugen-spec-proposal-0.5.5-vb-module-coins.md`); the output rule narrows §15.1's "any bytes".

Tier: within the network upgrade (Yugen's activation), the smallest rung: a skip and a refusal on the
bundle path, no new field, no new state; both bind only post-activation blocks. kogany will need the
same rules when it implements VB records (record it in the kogany plan's findings log until then).
Tests: gtest `Yugen.BundleVbRecordsConnect` (a tracked coin and a same-block coin skipped; an unknown
answer a local error, never invalid, and a recorded mask followed; a V-shaped record output, YED and
other tag, refused), `Yugen.BundleRecordInputTrackedByModule` (the module does not refuse the bundle; the
leaf way burns); test_bitcoin `yellowback_index_tests/tracks_at_parent_unknown_unless_at_parent`; rpc
`yugen_bundle_vb_module.py` (a block whose bundle deposits a token with a broken signature: an unhealthy
index stops the node and the block is not invalid, the block connects with the deposit skipped, and
`verifychain 4` passes over it; both failed before the fix). `-yellowbacktestfault=storage:mempool`
(regtest) makes the next `MempoolCheck` fail, leaving the node running with an unhealthy index.

## Review fixes (C-1, P-1, 2026-11-26)
- C-1: `DecodeRecord` found a repeated deposit input by scanning the record's earlier inputs, quadratic
  in the input count: ~53,000 inputs in a ~1.96 MB bundle took ~725 ms per decode, twice under `cs_main`
  per relayed transaction. A set of the prevouts seen (yugen-ref `Bundle::decode`'s `BTreeSet`, per
  record, the same `bundle-vin` verdict at the same input) makes it O(n log n). Test:
  `Yugen.DecodeRecordManyInputsIsFast`.
- P-1: the helper (`contrib/yugen-leafverify`, `bundle`) cleared `proofs_bound` before
  `Bundle::decode` and `bundle_views`, so a bundle the node's reading accepts but the reference
  refuses (B1: anchor order, payee table, unused anchor, mixed schemes, a sixth merge level, more
  than 16,384 transfers; B2 to B4: anchors) came back as a possibly corrupt body: the block was
  refetched forever while the peers that served it were banned. The bundle bytes are committed by the
  txid and the height by the block, so such a refusal now reports `proofs_bound` (a verdict on the
  block); only a missing request field does not. The node's own reading now has the reference's
  limits too: a merge needs budget left (`BUNDLE_DEPTH_MAX` = 5 merge levels, was 6) and at most
  `BUNDLE_TRANSFERS_MAX` = 16,384 transfers (unreachable under the arity limits, kept for parity), so
  `depth-six` is refused by the node itself. Tests: the helper's
  `tests::structurally_invalid_bundle_is_bound` (`cargo test --release`), `Yugen.BundleVectors`.

## Known issues for beta4
- **K-1, consensus, not built: withdrawal classification (§13.3.5, §15.6 B6 "applied").** A spec
  0.5.4 node classifies each withdrawal: queued if `G + a > K`, immediate if `a ≤ τ` (100 YEC) and
  `I + a ≤ Ks`, else maturing (outputs spendable after `M` = 1,152 or 2,304 unpaused blocks); it
  keeps `G`, `I` and the queue per window, serves the queue, counts the fee excess to `G` and doubles
  `M` on the trigger outflow. This line makes every withdrawal's outputs immediate. A transaction
  spending a maturing output early, or a block whose withdrawals a spec node would queue, is valid
  here and invalid there: the two split. The spec does not mark the rules out of scope for beta4;
  §13.3.1 says no release may activate Yugen with the provisional safety parameters, so no public
  network activates Yugen on this line; it runs on regtest and devnets only. Building it is a pool-state change on leaves and bundles alike
  (window state and its undo, a locked-coin rule in `CheckInputs`, queue service in the block, the
  fee split); it must land, on every node line, before any activation height is set.
- **K-2, decision: a bundled deposit of a coinbase coin may have transparent change.** Spec 0.5.4
  §15.5 and §15.6 S2 list what may not be spent at `h` (coinbase maturity, exit maturity, a queued
  withdrawal's lock, a voided output) and nothing more; the script interpreter is the only other check
  on a deposit input. ycashd's `fCoinbaseMustBeShielded` (mainnet and testnet; off on regtest) is a
  rule of `CheckInputs` on a transaction's own `vout`, which a bundle does not have (B1a), so it does
  not reach a record. A leaf deposit of a coinbase coin with change is refused on mainnet by that
  rule; the same deposit in a bundle is valid. The node follows the spec: adding the rule to records
  here alone would split this line from a spec node. Question for
  the specification: either add "a coinbase coin with change in `vout_i`" to the deposit-coin rule
  (a failure, B6, like the script rule) or state that the shielding rule does not apply to records.
  Maturity (100 blocks) is applied (S2).
- **K-3, wallet and indexes: record coins are not tracked.** A bundle's inputs and outputs are not
  in its `vin`/`vout`, and the wallet and the insight indexes read only those. What a user sees:
  (a) a withdrawal (`z_sendmany` from the Yugen account to a transparent address of this wallet, or
  the Yugen -> Sapling hop to a keypool address) that a host carries in a bundle is never credited:
  `getbalance`, `listunspent` and `z_listunspent` do not show it, coin selection cannot use it, and
  the leaf transaction the wallet stored, and for the Sapling hop the Sapling transaction that spends
  it, stay unconfirmed (the bundle superseded both in the pool), so the Sapling recipient is not paid
  by that operation; (b) the transfer itself is final and the Yugen account sees it (by nullifier,
  `gettransferstatus`). The coin is not lost: it is in the UTXO set at the bundle's txid
  (`gettxout <bundle txid> <index>`, indices across all records, `yugen_getblockdata` `bundles`), at
  an address whose key the wallet holds, and spends with `createrawtransaction`,
  `signrawtransaction` and `sendrawtransaction`. (c) A deposit whose coin is a wallet coin (not the
  Yugen engine's deposit address) is spent by a bundle the wallet does not see: the wallet keeps the
  leaf as unconfirmed, and if it never stored a leaf it counts the coin as unspent and a send that
  selects it is refused (`bad-txns-inputs-missingorspent`). (d) `getaddressbalance`,
  `getaddressutxos`, `getaddressdeltas` and `getspentinfo` (`-insightexplorer`) do not list record
  outputs or the coins a bundle spent, so an explorer shows neither. Fixing it needs the wallet and the
  indexes to read a bundle's applied records (the undo mask) where they read `vin`/`vout`; not small,
  left for beta5.

## Review fixes (independent review of the consensus commit, 2026-11-25)
- H-1, C-1 (sidecar swap): the helper checks B5 (both proofs non-empty, within `PROOF_BYTES_MAX`,
  hashing to the committed hashes) before anything else about the proofs, and no longer applies a
  leaf's `LEAF_PROOF_MAX_B` to a bundle's proof B (honest bundle proofs up to `PROOF_BYTES_MAX` were
  refused). Its bundle reject is `REJECT {"proofs_bound":b,"reason":r}`; ycashd treats a reject as a
  verdict (`bad-yugen-bundle-proof`) only when `proofs_bound` is true, else
  `bad-yugen-bundle-proof-unbound`, `BodyCorruption::Possible`.
- H-2 (local fault as a verdict): the helper's verdict exit is 10. Exit 1 (a Rust `main` returning
  `Err`), 101 (a panic) and every other code is a failure; request fields the node writes are
  failures when missing; b2verify's exit 1 is a verdict only with its `REJECT <label>` line.
- H-1 stall: a failure while a block connects (helper, timeout, out of memory, a state fault) is
  `yugen-verifier-failed`, DoS 0, `BodyCorruption::Possible`: the block is not marked invalid, its
  sender is not scored, and its body is reset, so it is fetched again from any peer and checked again.
- M-2: a global budget of Yugen transactions from peers judged per minute, whitelisted peers
  included (`-yugenpeerverifyrate`, default 6; others wait for `AskFor`'s retry); a mempool
  candidate's helper deadline `-yugenmempoolverifytimeout` (default 120 s; a bundle's System B root
  verification takes 30 to 100 s on the devnet, a leaf's verification about 1.5 s).
- Mempool replay (item 4): a refused candidate is remembered by its txid, wtxid, proofs (inline or
  from the store) and the tip (bounded, 20,000), and an identical copy from any peer is dropped
  before any check or budget is spent. Failures are not remembered.
- M-3: every refusal in `CheckMempoolTx` (anchors, nullifiers, turnstile, proofs, all judged at the
  node's tip) is DoS 0; structure stays DoS 100 in `CheckTransaction`.
- M-4: no root helper run for a trial (mempool candidate, template, `fJustCheck`); the proof cache
  (16 entries; the files are the store), the bundle result cache (4,096) and the refusal cache are
  bounded. Open: the root is still recomputed from the whole commitment list once per connected
  block with commitments (an incremental frontier needs a helper command and state for it); the
  proof files (`<txid>.bin`, `blk-<hash>.bin`) and `PoolState::blocks` are never pruned.
- C-2 and the stale sidecar: `SaveSidecar` replaces any stored sidecar of the block (a copy without
  one removes it), a body reset deletes it (`ResetBodyStateForSubtree`), `AttachSidecar` prefers a
  stored sidecar only when it fits the block (one entry per bundle of the block, two proofs each),
  and a block is served with its sidecar only once it connected (`BLOCK_VALID_CONSENSUS`).
- Item 5: with a Yugen height, `-yugenb2verify` and `-yugenbplan` are required at startup (a file
  and a directory); on regtest they may both be left out (leaf-only suites, stub bundle proofs), with
  a warning in the log.
- Item 6: `YugenRelayDepth` answers 0 at once for a transaction that is neither Yugen nor has a Yugen
  ancestor in the pool (a set kept at admission) and walks at most 100 ancestors otherwise.
- Lows: `bad-yugen-leaf-weight` is a verdict when the excess is in committed bytes; bytes after
  `vtx` before activation are ignored, as upstream does, and bytes after `vtx` that do not read as a
  sidecar are ignored at any height; the regtest restriction of `-yugenteststubproofs` and the
  Vault-before-Yugen check are part of the consensus commit (the stub check also inside
  `yugen/state.cpp`).
- The classifier (`IsBundleEncoding`, N-D8): since spec 0.5.3 the first byte, `bundle_version`
  `0x80`; the structural heuristic and its misread rate (recorded in
  `doc/yugen-spec-proposal-0.5.3-envelope-kind.md`) are gone.
Tests: `qa/yugen/test_leafverify.py` (helper contract), helper unit test
`b2verify_exit_one_without_a_reject_line_is_a_failure`, gtests `Yugen.LeafEnvelopeIsFixed`,
`Yugen.LeafWeightClass`, `Yugen.PeerVerifyBudget`, and new cases in `yugen_bundle.py` and
`yugen_strip.py`.

## Review fixes (third round, 2026-11-25)
- Block size (high): `CheckBlock` measures `MAX_BLOCK_SIZE` (W2) on the block without its sidecar
  (`SER_DISK`, which never carries it); W3 bounds block and sidecar together in `yugen::ConnectBlock`.
  The 4.25 MiB message limit (`net.h`) moved into the consensus commit, so that commit alone relays a
  W3-sized block. Test: gtest `Yugen.BlockSizeExcludesSidecar` (1.99 MB block, 0.8 MB sidecar).
- Lost verdicts (medium): `yugen::ConnectBlock`'s inner state starts as a copy of the caller's, so
  it inherits the body-commitment flags; a spent nullifier, the turnstile, an anchor or a bound
  bundle proof is a verdict again (`BLOCK_FAILED_VALID`). Test: `Yugen.DoubleSpendBlockIsAVerdict`.
- Relay budget (high): the token is taken in `yugen::CheckMempoolTx`, after `CheckTransaction`, the
  structure, `PreCheckMempoolTx`, inputs and scripts and the refusal cache, just before the helper
  (`yugen::PeerVerifyScope` names the peer; no token is `yugen-verify-deferred`, re-asked in two
  minutes, never a refusal). A peer that took its share (`-yugenpeerverifyrate` / the peers that
  asked within the minute) takes a token only while one is left for each other peer that waited. A peer's
  back-off after a refusal doubles per refusal in a row, 10 s to 10 min, and restarts after 20 quiet
  minutes. Tests: `Yugen.PeerVerifyBudgetFairShare`, `Yugen.RefusalBackoffDoubles`.
- Helper retries (medium): `HELPER_RETRIES_MAX` (5) verifier failures of one block hash, then the
  block is no longer requested (`FindNextBlocksToDownload`) until a restart, with a log line; the
  same body (block hash and sidecar) failing a second time scores its sender 10 (`HELPER_SAME_BODY_DOS`), once
  per body, so a broken local helper cannot get honest peers banned.
  A leaf proof check and the registry root at connect time get the mempool timeout (at least 120 s,
  at most `-yugenverifytimeout`); a bundle and the note-tree root keep the full timeout. Test:
  `Yugen.HelperFailureRetriesAreBounded`.
- Proof store (low): no write for a trial (mempool candidate, template, `fJustCheck`), none when the
  file already holds the same proofs, and a bundle's own file is removed once its block is
  `MAX_REORG_LENGTH` deep and the block's sidecar file holds the proofs. The bundle result cache key
  includes `-yugenb2verify` and `-yugenbplan`. Tests: `Yugen.BundleTrialWritesNoProofFile`,
  `Yugen.BundleCacheKeyHasVerifierOptions`.
- Open (low, recorded with numbers): `Flush` writes the whole pool state each time (per nullifier
  68 bytes with its height, per commitment 48, per applied transfer its 232 or more bytes and txid,
  per block record about 150 bytes): about 0.5 GB at one million transfers. `ComputeRoot` passes the
  whole commitment list to the helper once per connected block with commitments (97 bytes a
  commitment as a hex line): about 190 MB a block at two million commitments. Both need state the
  helper does not keep today (a frontier command, an append-only state file), so they wait for the
  helper crate's next revision.
- Footprint: `runCommand` is upstream's again (`system()`); the fork helpers moved to
  `src/yugen/spawn.{h,cpp}` for Yugen code only, and every Yugen pipe is created close-on-exec
  (`PipeCloexec`), so a notify command's child never holds one. Residual: where `pipe2` is missing
  (macOS), a notify command forked between `pipe` and `fcntl` inherits that pipe (the window is two
  system calls, under `SpawnMutex` for Yugen forks only).
- The reset-root fix is `RestoreHeaderCommitment` (main.cpp, main.h), the shape the vault line
  carries, with its gtest `Validation.ResetBodyStateKeepsHeaderCommitment`.
- Spec 0.5.4 (approved; `doc/yugen-spec-proposal-0.5.4-bundle-envelope.md`): a bundle transaction's
  lock time is 0 and its expiry height `h_a + ANCHOR_WINDOW` for its first anchor table entry
  (`CheckLeafEnvelope`; test `Yugen.BundleEnvelopeIsFixed`, and `bundle_tx` in the functional
  tests writes it). Value balances in a bundle (§15.1 `VB` records, §15.5): built, N-D10. Open:
  kogany parity.

## B-RPC-2: `bundles` in `yugen_getblockdata` (yugen/brpc2)
RPC only; existing fields unchanged. Per bundle transaction of the block, in block order:
`{"txid", "stmt" (bstmt hex32: the helper's statement, proofs not re-checked; null if the helper
cannot say), "proof_hash_a", "proof_hash_b" (the encoding's last 64 bytes), "transfers" (n encoded),
"applied" (n not skipped, §15.6 S1), "transfer_indexes" (positions of the applied ones in
`transfers`, whose `txid` is the bundle's), "nf1" (per applied transfer), "proof_a_bytes",
"proof_b_bytes" (null if the proofs are not held), "fee_zat" (applied fees), "skipped_fee_zat"}`.
Bundled transfers have no txid of their own: the leaf transactions a bundle absorbed are matched
by `nf1` (as `gettransferstatus`). The block is read from disk on each call; `stmt` costs one
helper run per bundle (cached in process). Empty array for a block without bundles.

## Bundling is optional (rule; walk m4, 2026-11-25)

Rule: the chain's liveness and validity never depend on bundling. Bundle provers and
`yugen-bundlerd` are optional fee earners. A block with no bundle is valid, a template is built
from the mempool without waiting on any bundle, and every Yugen transfer can confirm as a leaf
within `LEAF_RESERVE` (`src/primitives/yugen.h`); the bundle limit (`miner.cpp`,
`BLOCK_WEIGHT_MAX - LEAF_RESERVE`) only caps bundles, never leaves. Removing the bundler at any
time leaves no state that blocks templates: bundles are not part of the pool state carried
between blocks, and a node rebuilds that state from blocks alone.

Evidence: a regtest devnet walk (2026-11-25; ycashd 27ad58ee1, yolo + stratum miner, two nodes, yewd
wallets, no bundle prover at any point):
- a) 321 blocks mined by yolo, 310 after Yugen activation (height 112); tips agree at every
  check; `getblocktemplate` 21-80 ms throughout.
- d) blocks 114..323: 210 blocks with zero Yugen transfers and bundles, all valid; turnstile
  `pool_balance_zat` 0 -> 0 on both nodes.
- b) wallet-proved shield (deposit), Yugen -> Yugen and withdrawal (`yugen_withdraw`) each mined
  as a leaf (230-240 leaf bytes, no bundle in the block); fee 255,600 zat each; withdrawal debits
  the turnstile by 2 YEC plus fee.
- c) `yugen-bundlerd` started with a leaf transfer pending and no prover, the chain mined 3
  blocks under it, a deposit queued, bundlerd SIGKILLed: both transfers confirmed as leaves,
  templates unaffected.
- e) both nodes restarted (tip and turnstile unchanged), node B wiped and resynced from genesis
  to the same tip and turnstile (1,098,722,000 zat).

Observed: each Yugen transfer confirmed one block after the block following submission. Cause
(read from code, not separately tested): yolo re-issues work only when its change key moves
(`src/template.rs` `ChangeKey`: height, target, header root, flags); the tx set is not in it, so a
transfer arriving after a job is issued waits for the next height. Not a node or bundling issue;
the fix is in yolo (a digest of template txids in `ChangeKey`, rate-limited).

## The wallet's Yugen account (yugen/account, 2026-11-25)

Design rule (decision Y-9): ycashd's own wallet has full Yugen functionality, as easy as Sapling (UX
non-negotiable). Built: `src/wallet/yugenaccount.{h,cpp}`, RPC changes in `src/wallet/rpcwallet.cpp`,
`src/wallet/rpcdump.cpp`, `src/init.cpp`.

What a user does:
- `z_getnewaddress yugen` -> the account's default short address (`yqrf…` on regtest, decision Y-15), the
  same on every call (its record is published at both hosts on each call); `z_getnewaddress yugen
  '{"onetime": true}'` -> the one-time form (short address + a fresh single-payer payment request).
- `z_getbalance <yq address> (minconf inZat)`: spendable notes (under the wallet anchor); minconf 0
  adds pending ones. `z_gettotalbalance`: `yugen` (in `total`), `yugen_pending`,
  `yugen_outgoing_pending` (queued payments to short addresses), `yugen_error` if the engine failed.
- `z_listaddresses` lists the account's addresses; `z_listunspent` adds rows with `"pool": "yugen"`
  (a filter of Yugen addresses lists only them; a mixed filter is refused);
  `z_listreceivedbyaddress <yq address>` lists every note with `memo` (hex) and `memoStr`;
  `listtransactions` adds `receive`/`send` rows with `"pool": "yugen"` (newest first; a send row's
  amount = notes spent - change - transfer fee); `gettransaction` answers a Yugen-only txid and adds a
  `yugen` object to a wallet transaction that is also a Yugen transfer of the account.
- `z_sendmany <yq address> [{one recipient}]`, one operation id: to a Yugen address (short, full or
  one-time) a leaf transfer from the account's notes (a short address not yet resolved is queued:
  `z_getoperationstatus` says `"pending"` until the scheduled sync resolves and sends it); to a
  transparent address (P2PKH, SLH-DSA, FN-DSA) a withdrawal through the turnstile; to a Sapling address
  a withdrawal of amount + 1,000 zat to a fresh keypool address of this wallet, then a stock
  `z_sendmany` of exactly that coin with the memo (`AllowRevealedSenders`); the result names
  `withdraw_txid` and `sapling_txid`. A memo is UTF-8 text (the engine's form); to a transparent
  address it is refused. The fee is the fixed transfer fee (255,600 zat).
- Receiving: the scheduler thread runs the engine's `sync` once per 16-block boundary after a random
  delay in [0, `-yugensyncdelay`] (default 60 s) (decision Y-16; spec §17.8 item 1): the engine's two-host
  session sends exactly its fixed number of address queries to each host (real ones for queued
  payments, the rest cover) and fetches the package buckets of every epoch since its last session;
  it retries while the hosts have not taken the boundary's snapshot. Notes are found by trial
  decryption of the note packages (hosts) and of the chain (requests, change).
- Backup: `dumpwallet`/`z_exportwallet` write `yugenseed=<hex> # yugenaddr=<address>`;
  `importwallet`/`z_importwallet` create the account from that line when the wallet has none (refused
  if it has one with another seed). `-rescan` clears the account's chain and host state (keeps seed,
  counters, issued requests, resolved addresses, queued sends); the next call rebuilds it.

Flags: `-yugenprover` (the yewd-yugen binary, already used by z_sendmany) is the engine; `-yugenwallet`
overrides it. `-yugenhosts` as before. State: `<datadir>/<net>/yugenwallet/` (`wallet.json`, the
engine's store; `ycashd-addresses.txt`, the addresses handed out).

### Decision N-A1: the engine is yewd's Yugen wallet, run as a child process per call
Options: (a) link the yew `yewd-yugen` crate into ycashd's Rust library (path dependency, cxx bridge);
(b) a child process per call, the same binary `-yugenprover` already names, as `yugen-sendbuild` does
(N-S1); (c) port keys, scan, host client and builder to C++. (c) duplicates the specification's
reference code and the wallet in a second language. (a) brings the wallet's workspace, toolchain
(1.98.1) and the vendored proof crates into ycashd's offline vendored build (the reason N-D1 keeps the
verifier out); the provers would share ycashd's address space (Y-W2 isolates them). Chosen (b): the
account is the yewd engine byte for byte (same keys, scan, host sessions, cover queries, builder,
provers); ycashd adds RPC shapes, the scheduler and backup. Costs: a process start and a chain scan
(`yugen_getblockdata` per new block) per call; the engine calls back into this node's RPC, so every
call is made with no lock held (`yugenaccount.h` LOCKING), and calls are serialised (one `wallet.json`),
so a send that is proving (minutes) delays balance calls. The engine authenticates with `-rpcuser`/
`-rpcpassword` when set (visible in `ps` on the host), else the cookie file. Reversed when the
wallet crate builds inside ycashd's vendored set: then call it through cxx, same RPC layer.

### Decision N-A2: the account seed from the wallet's mnemonic seed
`yugen_seed = BLAKE2b-256(personal "Ycash_YugenSeed_", BIP 39 seed (64 bytes))`, then the spec's
`derive_account(yugen_seed, network, 0)` (spec §4; yewd's `Account::from_seed`). The same mnemonic gives
the same Yugen addresses in any wallet applying this rule. yewd today creates its Yugen seed from 32
random bytes (`Engine::open`), so yewd must adopt this rule for the same-seed property (open item for
the wallet agent: derive from yewd's own BIP 39 seed the same way). Options: (a) this derivation;
(b) a ZIP-32-style path under the Sapling master key (ties Yugen to Sapling key code); (c) a random
seed kept only in the backup line. (a) chosen: one hash, independent of Sapling, recoverable from the
mnemonic alone. The derived seed never goes on the engine's command line: when the account
is created (wallet unlocked) ycashd writes it into a new `wallet.json` (mode 0600) and the engine
opens that. RPC credentials reach the engine as a cookie file (the node's own, or a 0600 file holding
`-rpcuser:-rpcpassword`, removed after the call). Reversed by a seed sealed in the wallet database.

(The plaintext-seed limitation recorded here before is closed by N-A5.)

### Decision N-A5: the seed at rest (yew `yewd/yugen/docs/yugen-seed-at-rest.md`, Y-W12)
The Yugen seed lives only in `wallet.dat`: record `yugenseed` in a plain wallet, `cyugenseed` (AES-256-CBC
under the master key, IV = `BLAKE2b-256("Ycash_YugenSd_FP", seed)`, the mnemonic seed's scheme) in an
encrypted one (`CCryptoKeyStore::{Set,Get,Have}YugenSeed`; `EncryptKeys` encrypts it, the crypted write
erases the plain record; `encryptwallet` ends with the stock `CDB::Rewrite`; `walletpassphrasechange`
re-wraps only the master key). Per engine call, only while unlocked, the seed goes to `yewd-yugen` on a
pipe dup'ed to fd 3 (`-seedfd=3`): never argv, env or a file. `wallet.json` holds `seed_fp` and no seed,
written 0600 atomically (tmp, fsync, rename, directory fsync). Locked: balances and listings read the
last state (no engine call, no scheduled sync); `z_sendmany` from the account and `z_getnewaddress
"yugen"` fail with -13 ("Please enter the wallet passphrase with walletpassphrase first."). Migration: a
`seed` field in `wallet.json` moves into `wallet.dat` at start (plain wallet), `walletpassphrase`,
`encryptwallet` (before encrypting; refused if it cannot) or the next call, and the file is rewritten
without it, the old content overwritten with zeros first. These never wait for a running engine call
(try-lock: the engine's RPC callbacks need cs_main). Backup unchanged: `yugenseed=` (needs unlock).
The overwrite is best effort only: on APFS (copy-on-write) and on SSDs (remapping) the old blocks may
survive until reused, so a seed that was ever in a plaintext state file must be treated as exposed to
anyone who could image the disk; no temporary or renamed copy is left (the qa test walks every file
under the data directory). Found and fixed on the way: stock `encryptwallet` left the plain
`mnemonicphrase` record in `wallet.dat` (and so in the BDB log after the restart); the crypted write
now erases it, like `yugenseed`.

Review fixes (2026-11-25; Original, the Ycash developers): (1) `-rescan` runs the migration first
(`ResetChainState` returns false and init stops with "-rescan refused" while it cannot, e.g. a locked
wallet: start without `-rescan`, unlock once, restart with it); it never drops a seed. (2) The seed
record is durable before any other copy is destroyed: `CWallet::YugenSeedDurable` flushes the BDB log,
takes a checkpoint (the environment runs `DB_TXN_WRITE_NOSYNC`), syncs `wallet.dat`, `database/` and
the data directory (`F_FULLFSYNC` on macOS), and reads the record back and compares it; only then is
the state file rewritten. (3) `WritePrivate` opens the old file first (`O_NOFOLLOW`, regular files
only), renames the new one over it, syncs the directory, and only then zeroes the old inode through
the still-open descriptor. (4) `z_exportwallet` refuses (before creating the file) when the account
exists and its seed is not available; it never writes a dump without it. (5) The seed stays in
`SecureString`/`CKeyingMaterial` on dump, import and migration (the import line and its split words
are cleansed; the state file is read into a secure buffer and the parsed seed string cleansed);
comparisons are constant time. (6) The seed pipe is created close-on-exec (`pipe2` where present,
else `pipe` + `FD_CLOEXEC` under `SpawnMutex`, which every Yugen fork holds; every Yugen child closes
inherited descriptors from 3 up; `runCommand` is upstream's, see the third review round); the
seed is framed as hex and `'\n'` and the engine reads to the newline. (7) `gettransferstatus`
matches either nullifier of a pending transfer. (8) While a locked encrypted wallet leaves a plaintext
legacy seed in the state file a warning is logged (at start, at a failed migration, hourly from the
sync thread). Test: `qa/rpc-tests/yugen_wallet_rescan.py` (imported-seed legacy file + `-rescan`,
then a spend; locked refusal; dump refusal).

### Decision N-A3: z_sendmany from the account, one call for every destination
Yugen -> Yugen and Yugen -> transparent are the engine's `send`/`withdraw`. Yugen -> Sapling is two
transactions (a Yugen transaction has no Sapling part, W-TX): withdrawal to a fresh keypool address,
then the stock Sapling send of that whole coin; the same shape as yewd's Y-W9 and the reverse of N-S3,
and as visible (the hop links the two; decision Y-10's turnstile crossing). One operation id.

### Decision N-A4: backup by the seed line; counters on restore
The mnemonic alone restores the account (N-A2); the `yugenseed=` line also restores an account whose
seed is not the mnemonic's (an account imported from elsewhere). Finding: the engine derives a dummy
spend's nullifier from `dummy_counter`, which a seed-only restore cannot recover, so a restored
account starting at 0 would repeat an earlier dummy nullifier and have its transfer refused (the same
holds for yewd restoring from its seed). Fix here: a restore starts `dummy_counter` and `next_change`
at a random point in [2^24, 2^31). Fixed in the engine (yew yugen/seedsafe): the dummy counter is per anchor
height (spec §5.6) and a counter whose dummy nullifier the node reports mined or pending
(`gettransferstatus`) is skipped, so ycashd no longer randomises `dummy_counter` (`next_change` still is).

### Not done / open
- yewd adopts N-A2 (yew yugen/seedsafe: the signer derives it; shared vector `3a3287aa…d538c` for the phrase
  "abandon x11 about" in yewd-signer, yewd-yugen and qa/rpc-tests/yugen_wallet_encrypted.py). Same addresses
  across yewd and ycashd follow from the same seed; not run end to end through yewd.
- `listtransactions` merges Yugen rows by confirmations before from/count paging; `asOfHeight` omits Yugen rows; no
  `listsinceblock`/`z_viewtransaction` rows.
- `otag_counters` are not randomised on restore (possible otag reuse after a seed-only restore).


## Helper build

`make` (and so `./zcutil/build.sh`) builds the three helper processes and copies them next to ycashd
(`src/Makefile.yugen.include`; `--disable-yugen-helpers` skips them):

| binary in `src/` | crate | ycashd option | default |
|---|---|---|---|
| `yugen-leafverify` | `contrib/yugen-leafverify` | `-yugenverifier` | `src/yugen-leafverify` beside ycashd if present, else `yugen-leafverify` on PATH |
| `yugen-sendbuild` | `contrib/yugen-sendbuild` | `-yugenbuilder` | `src/yugen-sendbuild` beside ycashd if present |
| `yewd-yugen` | the wallet's `yewd/yugen` workspace (yew, pinned) | `-yugenprover` | none: without it the node keeps no Yugen account (N-A1) |

- Each is its own Cargo workspace with its own lock and toolchain (`rust-toolchain.toml`, Rust
  1.98.1), so it is built with the rustup `cargo` (`YUGEN_CARGO`), not ycashd's `$(CARGO)`, with
  `--release --locked` (plus `--offline` unless `--enable-online-rust`, as ycashd's Rust build),
  into one target directory, `target/yugen-helpers/`, whatever `CARGO_TARGET_DIR` says.
- Dependencies are Yugen repositories checked out at the full commits in `contrib/yugen-*/PINS`
  into `contrib/yugen-*/deps/` (git-ignored) by `contrib/yugen-pins.sh` (called by
  `contrib/yugen-*/scripts/deps.sh`): from the public URL in PINS, or from `$YUGEN_LOCAL_ROOT/<path>`
  when that is set (local development; layout `yugen-spec`, `yugen-falcon`, `yugen-proof-a`,
  `yugen-proof-b2`, `yew`). A checkout already at its pin is reused without a fetch.
  `yugen-sendbuild` and `yewd-yugen` build from the wallet (yew), whose `yewd/yugen/deps` is pointed
  at the same checkouts.
- Offline (default configure): depends vendors the helpers' crates.io dependencies into ycashd's
  vendored directory (`depends/Makefile`, `NO_YUGEN_HELPERS=1` to skip), so the helpers build from
  a cold cargo cache; see `doc/yugen-release.md`.
- Tests: `qa/rpc-tests/test_framework/yugen_util.py` points every Yugen test at `src/<helper>`;
  `YUGEN_LEAFVERIFY`, `YUGEN_SENDBUILD` and `YEWD_YUGEN` still override.
- Spend matrix: `qa/yugen/run-spend-matrix.sh <1-4>` runs one part of `spend_matrix.py` (optionally
  under a `$HEAVY_SLOT` wrapper), output in `target/logs/matrix-part<N>.{log,md}`.

## Design decisions referenced in the code (Y-n)

Numbered decisions of the Yugen node design, cited in comments as "decision Y-n":
- Y-3: ycash-dd (the v4.5.0 line) recognises the Yugen upgrade and refuses Yugen transactions and
  blocks after activation; ycash6 is the full Yugen line.
- Y-6: the Yugen RPCs are rpcversion 12.
- Y-9: Yugen is as easy to use as Sapling: (a) one "Yugen address" in every wallet interface, the
  wallet choosing static address or payment request; (b) `z_sendmany` builds a Yugen payment directly
  in one transaction from transparent (ECC, SLH-DSA, Falcon) coins, and Sapling <-> Yugen is one user
  action with the transparent hop done by the wallet.
- Y-10: the turnstile is enforced (spec §7.9 rule 4, §13.3.2): the pool balance is tracked and
  enforced, including between Sapling and Yugen.
- Y-13: the old test address strings (`yug1…`, `yugreq1…`) are refused everywhere.
- Y-14: every Yugen address carries "q": Falcon-512 `yqf` (mainnet), `yqtf` (testnet), `yqrf`
  (regtest); Falcon-1024 `yqk`/`yqtk`/`yqrk` reserved and refused until enabled.
- Y-15: the address shown by default is the 66-character short Yugen address; a one-time option
  gives the address plus a payment request.
- Y-16: wallets follow the spec's fixed sync schedule (every 16 blocks, cover queries, spec §17.8);
  a payment to a short address is pending until the next sync.
- Y-18: Yugen ships on its own branch and version line (6.23.x); parity: ycash6 and kogany agree on
  every block, ycash-dd agrees up to Yugen activation and refuses Yugen after it.

Activation: Yugen has no mainnet or testnet height; regtest activates it with `-nuparams`, and it
requires Vault active at or below its height. Transaction format (N-TX): the Yugen version group
(`YUGEN_VERSION_GROUP_ID`, ASCII "YGNG") is nVersion 4 with the Yugen field; its signature hash is
ZIP-243 extended by `hashYugen` over the transfer bytes.
