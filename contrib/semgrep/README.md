# Semgrep scanning

Static analysis with [Semgrep Community Edition](https://github.com/semgrep/semgrep) (the free, LGPL-2.1
CLI; no account, no Pro engine, nothing paid) on every push, every PR and nightly, with its
findings grouped by severity into **at most four PRs**, one per bucket, each with its own SLA. The same
pattern is in `ycash-dd`, `ycash6` and `librustzcash6`: the workflow, `scan.py`, `triage.py` and
`requirements.txt` are identical in all three; `config.json` (what to scan), `accepted.json` and `rules/`
are each repository's own.

| File | What it is |
|---|---|
| `.github/workflows/semgrep.yml` | the CI workflow (triggers below) |
| `contrib/semgrep/scan.py` | the scan, the same on a laptop and in CI |
| `contrib/semgrep/requirements.txt` | semgrep and its dependencies, hash-locked |
| `contrib/semgrep/triage.py` | `triage` (bucket the results) and `sync` (the per-bucket PRs); stdlib Python |
| `contrib/semgrep/config.json` | the pins and the policy: rule packs, buckets, SLAs, paths, what fails a PR |
| `contrib/semgrep/accepted.json` | findings accepted with a reason (they leave the buckets) |
| `contrib/semgrep/rules/` | Ycash-specific rules |
| `contrib/semgrep/findings/` | the ledgers the bucket PRs write (`<bucket>.md`, `<bucket>.json`) |
| `.semgrepignore` | paths never scanned (vendored upstream trees, fuzz corpora) |

## Running it

```bash
contrib/semgrep/scan.py                          # full scan -> semgrep-out/summary.md, findings.json
contrib/semgrep/scan.py --baseline upgrade/vault # only what this branch adds, as a PR would see it
contrib/semgrep/scan.py --baseline upgrade/vault --enforce   # and fail like the PR check does
contrib/semgrep/triage.py preview --findings semgrep-out/findings.json --out semgrep-out/preview \
  --repo boyfromcave/<repo> --sha HEAD            # the bucket PRs' titles, bodies and ledgers, as files
```

It needs `semgrep` at exactly `config.json` `semgrep_version` on PATH (`pip install semgrep==1.179.0`), or
`--install` to put it in a venv from the hash-locked `requirements.txt` (CPython 3.12, as CI does). The rules are fetched once into `~/.cache/ycash-semgrep`. Nothing goes
to semgrep.dev: no registry, no login, `--metrics=off`. A full scan takes about 2–3 minutes.

In CI the workflow can also be started by hand (Actions → semgrep → Run workflow), with `sync` to update
the PRs and `dry_run` to only print what it would do.

## Triggers

| Event | Scan | Result |
|---|---|---|
| `pull_request` | diff-aware against the PR base | step summary, code scanning; **fails on a new `critical` finding** (`fail_on`) |
| push to the default branch | full | step summary, code scanning, then `sync` |
| push to any other branch (not `semgrep/**`) | diff-aware against the default branch | report only |
| nightly 02:17 UTC | full, default branch | then `sync` |
| `workflow_dispatch` | full, chosen ref | `sync` when the ref is the default branch |

## Buckets and SLAs

Only rules whose `metadata.category` is `security` count. Each finding gets one bucket:

| Bucket | SLA | Typical finding |
|---|---|---|
| critical | 7 days | `CRITICAL` rules; `ERROR` rules with HIGH impact and at least MEDIUM likelihood and confidence |
| high | 30 days | other `ERROR`/`HIGH` rules |
| medium | 90 days | `WARNING`/`MEDIUM` rules |
| low | 180 days | `INFO`/`LOW` rules |

A LOW-confidence (audit-grade) rule drops one bucket, and so does code that never ships in a release
(`non_production_paths`; in the node lines `qa/`, `src/test/`, `contrib/`, `zcutil/`, docs …; in
librustzcash6 tests, benches, examples …). A local rule can pin its
bucket with `metadata.bucket`. The SLA clock starts on the day a finding is first seen and is carried
from run to run in the ledger.

## The bucket PRs

`sync` keeps one PR per non-empty bucket on the bot-owned branch `semgrep/<bucket>`, titled e.g.
`semgrep: 3 high findings, SLA 30d (due 2026-11-21)`, labelled `security`, `semgrep`, `semgrep:<bucket>`
and, once a finding is past due, `sla:overdue` (and `OVERDUE` in the title). Its diff is:

- the ledger `contrib/semgrep/findings/<bucket>.md` / `.json`: every finding with rule, location,
  fingerprint, first seen and due date;
- autofixes for that bucket's findings, **only** for rules listed in `config.json` `autofix_rules`
  (empty by default) and never under `autofix_never_paths` (consensus and vendored code: in the node
  lines script, primitives, PoW, `main.cpp`, the post-quantum code; in librustzcash6 the protocol,
  transaction, proof and Equihash crates). The packs' fix text is generic — it can call a module it
  does not import or misorder arguments — so a rule is opted in only after its fix has been reviewed.

Each run rebuilds the branch from the scanned commit and pushes only when the PR's change differs, so an
unrelated push to the base does not rewrite it. A bucket that becomes empty closes its PR and deletes the
branch. A ledger that went past due changes (`OVERDUE`), so an overdue finding re-surfaces even after a
merge. If people push commits to `semgrep/<bucket>`, the workflow stops force-pushing it: it only adds
ledger refreshes on top and never closes it. A PR closed by hand stays closed until its findings change.

Merging a bucket PR lands its autofixes and the ledger, as the reviewed record of what is open; the next
run then finds nothing to change and opens no PR until the findings do.

## Fixing or accepting a finding

Fix the code in any PR to the base branch (the PR check shows that the finding is gone), or on the
bucket's branch. Consensus code keeps its review gate (workspace `CLAUDE.md`, rules 2 and 7) whatever the
bucket says.

To accept a finding instead (false positive, or a risk taken knowingly), add it to `accepted.json` with a
reason a reviewer can check — by fingerprint (from the ledger or `semgrep-out/findings.json`):

```json
"findings": {
  "70677cd782d38469": {"rule": "python.lang.security.audit.dangerous-subprocess-use-tainted-env-args",
                       "path": "contrib/devtools/security-check.py",
                       "reason": "build-time tool; argv comes from the Makefile", "by": "@name", "date": "2026-10-22"}
}
```

or for a rule over paths: `"rule_paths": [{"rule": "c.lang.security.insecure-use-memset", "paths": ["src/crypto/pq/falcon/**"], "reason": "...", "by": "...", "date": "..."}]`.
A fingerprint is rule + path + the matched code, so it survives line moves but not an edit of the
flagged code itself. Inline `// nosemgrep` comments also work, but not in consensus code (no tidying
there); prefer `accepted.json`.

## Changing the policy

- **Rules**: `rule_paths` are directories of [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules)
  at `rules_commit`. Moving the pin changes the findings; do it in its own PR and read the diff of
  `semgrep-out/summary.md`. The rules are fetched at that commit, never copied in (their license is the
  Semgrep Rules License). `exclude_rules` drops a rule repo-wide, with the reason as its value.
- **Semgrep**: `semgrep_version` here and `requirements.txt` (its header has the command) move together;
  `scan.py` refuses a semgrep of another version.
- **What fails a PR**: `fail_on` (default `["critical"]`).

## Repository settings

- PRs opened with the default `GITHUB_TOKEN` need *Settings → Actions → General → Allow GitHub Actions to
  create and approve pull requests*, and they do not start other workflows. To have CI run on the bucket
  PRs, add a fine-grained token as the secret `SEMGREP_PR_TOKEN` (this repository; contents and pull
  requests: write); the workflow prefers it.
- Results also go to *Security → Code scanning* (category `semgrep`). Code scanning is GitHub's place to
  store and show the alerts of any scanner that writes SARIF; it is free for public repositories. Semgrep
  finds, GitHub displays: inline PR annotations, alert history, dismissals. The bucket PRs and their SLA
  ledger work without it.
