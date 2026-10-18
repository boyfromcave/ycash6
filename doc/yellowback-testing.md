# Yellowback testing: the golden vector and the independent checks

This file is the process the YED module's tests rely on (audit 03/T-1..T-4, 2026-10-13). The C++ state engine
(`src/yellowback/`) and the Python model (`qa/rpc-tests/test_framework/yellowback_model.py`) are two
implementations of one spec (`doc/yellowback-spec.md`); the tests are only a second opinion while the two change
independently. The rules below keep them independent.

## The golden vector

`qa/rpc-tests/test_framework/yellowback_golden.json` (and its byte-identical copy `src/test/data/yellowback_golden.json`,
checked by `src/test/gen_yellowback_corpus.py --check`) is a synthetic regtest chain built by `build_golden()` in
`test_yellowback_model.py`. It is replayed by the model (`test_golden_vector`) and by the C++
(`yellowback_state_tests/statehash_golden_vector`); both must reach the same `stateHash`, and the C++ pins it as
`GOLDEN_HASH`. Its rejected blocks (U-21: one per consensus verdict the vector covers) are the part that is a
verdict; the accepted blocks pin serialisation, evaluation order, undo-to-empty and cross-line parity (the file is
byte-identical on `ycash-dd` and `ycash6`).

**A rule change lands as three kinds of commit, never fewer:**

1. **(a) the rule** — `src/yellowback/*` plus its C++ unit test with the exact reject reason (`yellowback_state_tests.cpp`,
   `// Rule:` tagged);
2. **(b) the model** — `yellowback_model.py` plus its unit test in `test_yellowback_model.py`;
3. **(c) the golden regeneration**, in a commit of its own: `test_yellowback_model.py --write-golden`, the copy into
   `src/test/data/`, `GOLDEN_HASH` and the C++ `expected` map of rejected blocks in `statehash_golden_vector`
   (those two are the vector's manifest, not a rule), and `build_golden()` when the sequence itself changes. The
   commit message carries the new `stateHash`, the file's sha256 and the command. It touches nothing under
   `src/yellowback/` and no line of `yellowback_model.py`.

**The reviewer recomputes the hash independently** and records it in the PR body: check out commit (b) (or (c)'s
parent) on a clean tree, run `test_yellowback_model.py --write-golden`, `sha256sum` the file, and compare with (c).
A regeneration whose only justification is "the C++ changed" is refused: the C++ and the model must agree on the
rule before the vector moves. When a new rejected block is added, one reviewer re-derives the model's verdict for
it from the spec text before approving.

Checks that enforce it:

- `test_yellowback_model.py --check-golden` (CI `python` job, both lines) rebuilds the sequence and compares the
  **whole document** with the committed file, byte for byte; a hand edit of the hash or of any block fails.
- `qa/yellowback-audit.sh`'s **golden-separate-commit** check (report-only for one release cycle, then blocking): over the
  branch's commits (`YB_GOLDEN_BASE..HEAD`, default the merge base with `origin/upgrade/vault`), a commit that touches
  either golden file must touch nothing under `src/yellowback/` and must not change `yellowback_model.py`.
- The CI step **Cross-line identity (qa/yellowback-cross-line.manifest)** (and ycash-dd's audit leg of the
  same check) runs `qa/yellowback-cross-line.py`. The manifest names the nine vector files, the qa golden
  and model sources, `src/pqkey.{h,cpp}`, `doc/yellowback-spec.md`, and the trees `src/crypto/pq`,
  `src/vault` and `src/yellowback`. A file under those trees may differ only when the manifest pins both
  sha256 hashes (the 11 reviewed 6.20.0 shims). Editing a pinned file fails until both lines update the
  manifest together. `qa/yellowback-cross-line-trees.py` still checks the two overlay trees against
  `qa/yellowback-cross-line-allow.txt` with the same pins.
  Locally: `python3 qa/yellowback-cross-line.py --this-line y6 --other-dir ../ycash-dd --other-rev upgrade/vault`.

The state hash lives in two places with distinct roles: the C++ `GOLDEN_HASH` (the reviewer-recomputed pin) and the
file's `stateHash` (the artifact). The Python tests read the file; they keep no third copy.

## Independent arithmetic

`test_framework/test_yellowback_math_spec.py` re-derives every money formula of the module (MINT-5, FEE-1′, IT-9′,
AFEE-1, RED-4, RED-5/5′, HALT-2, MINT-6) in exact rationals (`fractions.Fraction`) from the spec's prose, in the
units the spec states them in, and checks that the model's integer function equals the rational rounded in the
direction the spec names (the owner pays up, a payee rounds down, "underwater" is a strict `<`), over 10^5 seeded
draws per function. `--write-cases` writes `src/test/data/yellowback_math_cases.json` from the rationals (never from
the model), and `yellowback_math_tests/math_spec_rational_cases` replays it through `math.h`. A disagreement is a
consensus finding for the review gate; it is never "fixed" in the test. The file's author and reviewer should be
people who have not read `math.h` or the model's arithmetic; the PR names them.

## Running

```
cd qa/rpc-tests
../../../../.venv/bin/python -m unittest test_framework.test_yellowback_model test_framework.test_yellowback_math_spec
../../../../.venv/bin/python test_framework/test_yellowback_model.py --check-golden
src/test/test_bitcoin --run_test='yellowback_*'          # from the tree root
```
