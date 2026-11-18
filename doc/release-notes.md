(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

Next release (beta4), changes since 6.22.0-beta3
------------------------------------------------

- **Pool quote agent: one fetch and one `yed_setquote` per block.** `yellowback-quote` polled every
  30 s, and every `yed_setquote` rebuilds the node's block template (2-3 rebuilds per 75 s block).
  `poll_seconds` now defaults to 75 (configurable; 60-75 s suits the 75 s block), still pushing on
  every poll so the tag's price is never older than one poll; `silence_seconds` is 180 so one missed
  fetch keeps a source. A node where Yellowback is not active yet is reported once and asked again
  every poll. Agent only; no node change (beta4 item 3b; `doc/yellowback-mining.md` §4).
- **Snapshot restores: a mainnet restore with the node check is no longer refused.** In beta3,
  `contrib/bootstrap/ycash-bootstrap` with `--ycashd`/`--cli` refused every mainnet restore: before
  Vault is active `vault_getinfo.dbtip` is null, and the tool recorded no vault state hash where the
  bundle carries the empty state's. It now compares `vault_getinfo.statehash` (the empty state's
  hash before Vault is active, as the publisher records it and `FORMAT.md` defines it) and still
  refuses a vault database at a different block. The README's exit statuses are corrected (1: an
  option refused before the restore starts). Proven against the signed mainnet bundle at
  3,105,000 (ycash-dd #200, ycash6 #139).
- **Security tooling: chrono RUSTSEC-2026-0543 is recorded as informational until 2027-02-15.**
  chrono is unmaintained (no vulnerability, no fixed version) and reaches the attestor agent's lock
  file only through a Windows-only dependency; the attestor agent is not built for Windows. Accepted
  by the Yellowback lead architect on 2026-11-18 (ycash-dd #201, ycash6 #140). No change to the node.
