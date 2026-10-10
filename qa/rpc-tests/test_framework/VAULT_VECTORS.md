# vault_vectors.json — the vault primitive's golden vector

`src/test/data/vault_vectors.json` is written by
`qa/rpc-tests/test_framework/gen_vault_vectors.py` (pure Python, `test_framework/vault.py`)
from fixed private keys, and replayed against the C++ by `src/test/vault_vectors_tests.cpp`
(docs/plans/yellowback-upgrade-plan.md §15.9). The file is **byte-identical on both node lines**
(ycash-dd and ycash6). Regenerate, or check, with the workspace venv:

```
.venv/bin/python qa/rpc-tests/test_framework/gen_vault_vectors.py           # write
.venv/bin/python qa/rpc-tests/test_framework/gen_vault_vectors.py --check   # compare only
.venv/bin/python -m unittest qa/rpc-tests/test_framework/test_vault.py      # includes --check
```

## Conventions

- Every byte string is lowercase hex.
- Ids, txids, set ids and hashes are in **internal byte order** (`uint256::begin()..end()`,
  `uint256(ParseHex(hex))` in C++, `bytes.fromhex(display)[::-1]` from an RPC txid).
- A `prevout` is the 36-byte `COutPoint` serialisation: txid (internal) || n (u32 LE).
- Message digests (`actMsg`, `setSigMsg`, `msg`) are the 32 bytes the hash produced, i.e. the
  bytes `CKey::SignCompact(uint256)` signs.
- Act integers are fixed-width little-endian; script numbers are what `CScript << int64_t` writes.
- `reason` strings are the Python codes and only informative; a C++ test asserts rejection.

## Schema

| Key | Entries | C++ assertion |
|---|---|---|
| `branchId` | `0x6d5b7a31` as an int | constant |
| `opcodes` | `CHECKSEQUENCEVERIFY` 0xb2, `CHECKSETSIG` 0xc0, `CHECKSETDORMANT` 0xc1 | constants |
| `keys[]` | `label, secret, pubkey` | (reference) |
| `pqOwner` | `label, seed (48), pk (32), owner{scheme, hash}` | the SLH-DSA-SHA2-128s owner of every V and I (quantum plan §4.3) |
| `vaults[]` | `name, params{tag, setId, cancelSetId, delay, ownerHeight, appHeight, owner{scheme, hash}}, script` | `BuildVault(params) == script`, `ParseVault(script) == params` |
| `vaultsInvalid[]` | `name, script, reason` | `ParseVault` fails |
| `intents[]` | `name, params{tag, recipientHash, vaultHash, delay, cancelSetId, setId, owner{scheme, hash}}, script, recipientScript, vaultScript` | `BuildIntent`, `ParseIntent`, `IntentFor(vault, recipient)` |
| `intentsInvalid[]` | `name, script, reason` | `ParseIntent` fails |
| `bonds[]` | `memberKey, locktime, redeem, spk` | `BuildBondRedeem`, `BondScriptPubKey`, `ParseBondRedeem` |
| `selectors[]` | `kind (V/I), scriptSig, selector, nArgs` | `ParseTemplateSpend(V or I, scriptSig)` |
| `selectorsInvalid[]` | `kind, scriptSig, reason` | `ParseTemplateSpend` fails |
| `acts[]` | `name, type, fields, payload, prevout, actMsg, signers, sigs, recovered, script, convicts?` | `DecodePayload`/`EncodePayload` round trip, `ActMsg`, `DecodeAct`/`EncodeAct` of the OP_RETURN, each sig recovers to `recovered`, equivocation proofs convict `convicts` |
| `actsInvalid[]` | `name, payload, reason, stage` | `decode`: `DecodePayload` fails. `field`: a context-free field rule fails (Python rejects at decode; C++ may at rule time) |
| `actScriptsInvalid[]` | `name, script, reason` | `DecodeAct` fails |
| `setSigMsgs[]` | `setId, role, prevout, sighash, msg` | `SetSigMsg` |
| `signatures[]` | `label, secret, pubkey, msg, sig, lowSFlipped` | `CKey::SignCompact(msg) == sig` (libsecp256k1's RFC 6979 nonce), `RecoverSig` → `pubkey`; both low-S branches covered |
| `signaturesInvalid[]` | `name, msg, sig, reason, nonStrictRecovers` | strict `RecoverSig` fails; `CPubKey::RecoverCompact` gives `nonStrictRecovers` where not null |
| `spends[]` | `name, tx, nIn, scriptCode, amount, branchId, sighash, setId, role, setSigMsg, signers, sigs, scriptSig` | `SignatureHash(scriptCode, tx, nIn, SIGHASH_ALL, amount, branchId) == sighash`, `SetSigMsg`, the scriptSig's sigs recover |
| `ownerSpends[]` | `name, tx, nIn, scriptCode, amount, branchId, sighash, selector, scriptSig` | the `pqOwner`'s SLH-DSA OWNER spend (selector 2, signed by `test_framework/pq.py`) passes `VerifyScript` under the vault flags |

The V/I owner (docs/plans/yellowback-quantum-spec.md §1) is `owner{scheme, hash}`: the slot is
`20 <hash> 51|52 c2` (`<ownerHash:32> OP_1|OP_2 OP_CHECKPQSIG`, 35 bytes, twice in V, once in I);
`hash` is the 32 bytes as pushed (`uint256` internal order). Both registered schemes are templates
(A-1: `owner-falcon-scheme-2`); a scheme outside {1, 2}, a scheme pushed as data (`01 01`), two
owner slots that differ, or the former `<ownerKey:33> OP_CHECKSIG` shape are not.

## Readings of §15 this vector pins

Where §15 left a choice, the Python took the reading below; the vector makes any divergence fail.

- **A-1 byte order.** `setId` is pushed and carried (act bodies, `setSigMsg`) as the 32 internal
  bytes of the `SET_CREATE` txid; prevouts as `COutPoint` serialises them.
- **A-2 "compressed".** 33 bytes with prefix 02/03, **no curve check** (the C++ library's reading,
  the smaller one). Off-curve keys parse (the `*-off-curve-accepted` acts); they can never sign or
  recover. (The V/I owner is no longer a secp256k1 key: see `owner{scheme, hash}` above.)
- **A-3 BIP68 height test** (reconciled: Bitcoin's test exactly). §15.2's prose says "coin height + n ≤ spending height − 1", but it
  also says "Bitcoin's CalculateSequenceLocks/EvaluateSequenceLocks", which give coin height + n
  − 1 < height, i.e. coin height + n ≤ height. The model follows Bitcoin: RELEASE is valid from
  `coinHeight + delay` and CANCEL (I-2, `h − coinHeight < delay`) until `coinHeight + delay − 1`,
  complementary with no gap. The literal prose would leave one height where neither works.
- **A-4 script numbers.** `delay`, `ownerHeight`, `appHeight`, bond `locktime` are `push_int`
  (OP_0, OP_1..OP_16, else minimal CScriptNum); parsers rebuild and compare bytes, so a data push of
  a small number, padding, or a PUSHDATA1 for a short push is not a template. `appHeight = 0` is
  OP_0. As §15.3 writes them, the I's `<delay> OP_CHECKSEQUENCEVERIFY` and the V's `<appHeight>
  OP_CHECKLOCKTIMEVERIFY` leave their argument on the stack as the true result (no OP_DROP).
- **A-5 re-lock accounting.** A re-lock output is a V, so V-1 adds its value to `lockedValue`;
  S-3's "`+= Σ re-lock`" is that same addition, counted once.
- **A-6 epoch roll.** The epoch is rolled before every read or write of a set's rate fields
  (unlock, owner spend, V creation), so the basis is `lockedValue` when the epoch began. A set's
  creation epoch has basis 0: with `rateLimitBps > 0` nothing unlocks until the next epoch.
- **A-7 act signature counts.** Exactly the number the rule names, all distinct: CREATE and
  EQUIVOCATION none; HEARTBEAT 1; JOIN 1 (`S_1` = member) + admission (`slashThreshold` current
  members if there are that many current members, else exactly the admitKey; an OPEN set takes
  `S_1` only); REMOVE and WINDDOWN exactly `slashThreshold`.
- **A-8 act carrier.** After OP_RETURN every element is a canonical data push; an OP_RETURN
  whose first push begins "YV" is an act and must parse; each `S_i` is 65 bytes.
- **A-9 context-free field rules** (reconciled: C++ rejects them at rule time via `vault::ActFieldsValid`) (CREATE ranges and flags, `bondLocktime < 500000000`,
  `burn ∈ {0,1}`, roles `∈ {1,2}`, equivocation signature headers 31..34) are rejected by the
  Python decoder; `stage: "field"` marks them so a C++ that checks them later still passes.
- **A-10 selectors.** An I takes only OP_1..OP_3; OP_4 on an I fails S-1.
- **A-11 extra pushes.** S-1 requires push-only, not an exact item count; with no CLEANSTACK
  `<x> <sig_1..k> OP_1` evaluates true. The model mirrors the interpreter (the top `k`).
- **A-12 order inside a transaction** (model): BIP68, bond spends (frozen → invalid, ACTIVE →
  WITHDRAWN), the template input's rules, V outputs (V-1), then the act.
- **A-13 frozen bonds** are frozen by outpoint: a burned or ejected member who rejoins with a new
  bond leaves the old one frozen.
- **D-1 `bondMin` range** (reconciled 2026-10-05, plan §15): `1 ≤ bondMin ≤ MAX_MONEY`
  (`MoneyRange`). `bond-min-above-max-money` is a stage `field` rejection; `set-create-open-max`
  uses `bondMin = MAX_MONEY`.
- Recoverable headers 33/34 (recid 2/3, R.x ≥ n) cannot be produced from real keys; the vectors
  cover 31 and 32 only.
