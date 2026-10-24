# Security CI

How this repository scans itself, what blocks a merge, where results go, and how to accept a finding.
Reporting a vulnerability is [SECURITY.md](SECURITY.md); this file is the automation. The same design
runs in every Yellowback repository; the tool versions are shared, and each tool is a pinned release
verified before it runs (a sha256 recorded in the workflow, or `pip install --require-hashes`).

Three workflows. None of them opens an issue; only Semgrep and Dependabot open PRs, a bounded number,
updated in place.

| Leg | Workflow / job | Scans | Blocks a PR when | Results |
|---|---|---|---|---|
| Semgrep | `semgrep.yml` | C++, Rust, Python, shell, Dockerfiles, workflows, secrets (`contrib/semgrep/config.json`), plus this repo's rules: RPC integer parameters range-checked where read, no floating point in the Yellowback module / vault primitive (`contrib/semgrep/rules/ycash-rpc.yaml`) | the PR adds a **critical** finding | code scanning (`semgrep`), at most four rolling `semgrep/<bucket>` PRs ([contrib/semgrep/README.md](contrib/semgrep/README.md)) |
| CodeQL | `codeql.yml` | `c-cpp`, `rust`, `python`, `actions`; `build-mode: none`, `security-extended`; vendored upstream trees excluded | never by itself (code scanning's PR check shows new alerts) | code scanning (`codeql/<language>`) |
| zizmor | `secops.yml` `zizmor` | every workflow, local action and `.github/dependabot.yml` | any finding | code scanning (`zizmor`), step summary |
| gitleaks | `secops.yml` `gitleaks` | secrets: the PR's commits; on push the pushed commits; nightly and on dispatch the full history | a leak not accepted | code scanning (`gitleaks`), step summary |
| OSV-Scanner | `secops.yml` `osv-scanner` | every tracked `Cargo.lock` and hash-locked pip requirement file | a known vulnerability not accepted | code scanning (`osv-scanner`), step summary |
| cargo-deny | `secops.yml` `cargo-deny` | RustSec advisories, bans and sources over the root `Cargo.lock` (`contrib/secops/deny-node.toml`; the root `deny.toml` stays upstream's licence policy), `--locked` | an advisory not ignored, a banned crate or an unknown source | job log |
| Checkov | `secops.yml` `checkov` | the Dockerfiles | a failed check not skipped | code scanning (`checkov`), step summary |
| Semgrep rule tests | `secops.yml` `semgrep-rules` | the local rules (`contrib/semgrep/rules/*.yaml`) against their annotated test files | a rule test fails | job log |
| Dependabot | `.github/dependabot.yml` | security updates for cargo, pip, github-actions, docker | — | one grouped `security` PR per ecosystem; version updates are off (every dependency is pinned and bumped deliberately) |

Beside these, the existing supply-chain checks stay as they are: upstream's `cargo vet` (`audits.yml`)
and the attestation agent's own `cargo audit` + `cargo deny` (`yellowback-tests.yml` `agent`).
Not run: `pip-audit` (OSV-Scanner reads the same PyPA advisories for both requirement files, and no
Python package ships from here). Nothing scans consensus code differently: findings under
`src/consensus`, `src/script`, `src/primitives`, `src/pow` and `src/main.cpp` are reported like any
other, and their fixes go through the consensus review gate, never through a scanner autofix.

Schedules (UTC): Semgrep nightly 02:17, secops nightly 03:43, CodeQL weekly Monday 04:41.

## Accepting a finding

Every acceptance has a reason a reviewer can check, next to the entry. A scanner is never switched off
to get a run green.

- **Semgrep**: `contrib/semgrep/accepted.json`, or `exclude_rules` / `audit_rules` / `bucket_overrides`
  in `contrib/semgrep/config.json` ([contrib/semgrep/README.md](contrib/semgrep/README.md)).
- **CodeQL**: dismiss the alert in code scanning with a reason ("false positive" / "won't fix" and a
  comment).
- **zizmor**: `.github/zizmor.yml`, per rule and file, with the reason as a comment; or an inline
  `# zizmor: ignore[<rule>] -- <reason>` on the line.
- **gitleaks**: the finding's fingerprint (`commit:file:rule:line`, printed by the job) in
  `.gitleaksignore`, under a comment saying why it is not a secret (test vector, public key, example).
  A path allowlist in `.gitleaks.toml` is only for golden-vector files. **A real secret is never
  accepted**: rotate it first, then decide whether history needs rewriting.
- **OSV-Scanner**: an `[[IgnoredVulns]]` entry in `osv-scanner.toml` with `reason` and an
  `ignoreUntil` at most 90 days out; on that date the scan fails again and the finding is re-triaged.
  A RustSec ID accepted there is also listed, with the same reason, in `contrib/secops/deny-node.toml`
  `[advisories]`.
- **Checkov**: `# checkov:skip=<CHECK_ID>:<reason>` in the Dockerfile. The reason is required: a
  skip without one fails the job, and only reasoned skips are removed from the SARIF the job
  uploads (`contrib/secops/checkov-sarif-skips.py`; code scanning does not honour SARIF suppressions).

## Repository settings this relies on

- Code scanning enabled (Settings → Code security). SARIF uploads from a fork's PR are skipped.
- Dependabot security updates enabled (Settings → Code security), for the grouped security PRs.
- Semgrep's `sync` job: "Allow GitHub Actions to create and approve pull requests", and optionally the
  `SEMGREP_PR_TOKEN` secret ([contrib/semgrep/README.md](contrib/semgrep/README.md)).
