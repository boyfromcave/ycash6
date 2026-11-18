(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

Next release (beta4), changes since 6.22.0-beta3
------------------------------------------------

- **Pool quote agent: one fetch per block, a push only when the price moved.** `yellowback-quote`
  fetched and called `yed_setquote` every 30 s, and every call rebuilds the node's block template
  (2–3 rebuilds per 75 s block for a 15-minute average). It now fetches every `poll_seconds` (75)
  and pushes only on a move above `min_move_bps` (10, 0.1 %), as a heartbeat every
  `heartbeat_seconds` (600, refused at 1,800 or more: `-yellowbackquotemaxage`), or when the node
  no longer holds a quote (a restart); `silence_seconds` is 180 so one missed fetch keeps a source.
  A node where Yellowback is not active yet is reported once and asked again every poll.
  `min_move_bps = 0` keeps the old behaviour (the devnet uses it). Agent only; no node change
  (beta4 item 3b; `doc/yellowback-mining.md` §4).
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
