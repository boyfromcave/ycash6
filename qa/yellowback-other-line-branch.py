#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Which branch of the other node line a cross-line comparison should read.

    qa/yellowback-other-line-branch.py --repo OWNER/NAME --branch B [--base upgrade/vault]
        CI: B on GitHub, judged by its pull requests (the API, token from $GITHUB_TOKEN)
    qa/yellowback-other-line-branch.py --dir DIR --branch B [--base upgrade/vault]
        local: B in the git repository at DIR, judged by ancestry and content

Prints the ref to compare with on stdout (B, or the base) and the reason on stderr; exit 0.
The same file on both node lines (qa/yellowback-cross-line.manifest).

Why (beta2 list item 63): both lines' CI compares with the other line's branch of the SAME name when
one exists, so a pair of pull requests lands together. After one side is squash-merged, its branch is
stale (old shim pins, old vectors) and broke the other side's later runs. A same-named branch is now
used only while it is live:

  CI (--repo):  an OPEN pull request from B          -> B
                no open one, and a MERGED pull request whose head is B's current tip -> the base
                no open one, and B adds nothing to the base (GitHub's compare: behind, identical, or no
                files changed since the merge base) -> the base
                otherwise (no pull request yet: a pair being prepared; or new commits after a merge) -> B
                the API unreachable -> B, with a warning (the behaviour before this check)
  local (--dir): B missing -> the base; B's tip an ancestor of the base, or merging B into the base
                changes nothing (a squash-merged branch) -> the base; otherwise B.

The base is BASE itself on GitHub; locally origin/BASE when the repository has it, else BASE.
Standard library only (CI runs it with the runner's python3).
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request


def say(msg):
    print(msg, file=sys.stderr)


def git(d, *args):
    r = subprocess.run(["git", "-C", d] + list(args), capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def resolve(d, name):
    """The first of refs/heads/NAME, refs/remotes/origin/NAME that exists, as (ref, sha)."""
    for ref in ("refs/heads/" + name, "refs/remotes/origin/" + name):
        rc, sha = git(d, "rev-parse", "--verify", "-q", ref + "^{commit}")
        if rc == 0 and sha:
            return ref, sha
    return None, None


def patch_id(d, *diff_args):
    diff = subprocess.run(["git", "-C", d] + list(diff_args), capture_output=True)
    if diff.returncode != 0 or not diff.stdout:
        return None
    r = subprocess.run(["git", "-C", d, "patch-id", "--stable"], input=diff.stdout, capture_output=True)
    out = r.stdout.decode().split()
    return out[0] if r.returncode == 0 and out else None


def squashed_into(d, tip, base_sha, limit=300):
    """The commit of base (first parent, newest LIMIT after the merge base) whose patch equals tip's whole change."""
    rc, mb = git(d, "merge-base", tip, base_sha)
    if rc != 0 or not mb:
        return None
    want = patch_id(d, "diff", mb, tip)
    if want is None:
        return None
    rc, revs = git(d, "rev-list", "--first-parent", "--no-merges", "-n", str(limit), mb + ".." + base_sha)
    for c in revs.split():
        if patch_id(d, "show", "--format=", c) == want:
            return c
    return None


def local(d, branch, base):
    bref, bsha = resolve(d, base)
    # Prefer the remote-tracking base: a main tree's local upgrade/vault can lag origin.
    rc, osha = git(d, "rev-parse", "--verify", "-q", "refs/remotes/origin/" + base + "^{commit}")
    if rc == 0 and osha:
        bref, bsha = "refs/remotes/origin/" + base, osha
    if bref is None:
        say("other line %s: no %s and no origin/%s" % (d, base, base))
        return None
    short_base = bref.replace("refs/heads/", "").replace("refs/remotes/", "")
    if branch == base:
        say("other line %s: %s (the base itself)" % (d, short_base))
        return short_base
    ref, sha = resolve(d, branch)
    if ref is None:
        say("other line %s: no branch %s there, so %s" % (d, branch, short_base))
        return short_base
    short = ref.replace("refs/heads/", "").replace("refs/remotes/", "")
    if git(d, "merge-base", "--is-ancestor", sha, bsha)[0] == 0:
        say("other line %s: %s (%s) is already in %s (merged or never moved), so %s"
            % (d, short, sha[:9], short_base, short_base))
        return short_base
    # A squash merge leaves no ancestry: merging the branch into the base changes nothing.
    rc, tree = git(d, "merge-tree", "--write-tree", bsha, sha)
    _, btree = git(d, "rev-parse", bsha + "^{tree}")
    if rc == 0 and tree.splitlines() and tree.splitlines()[0] == btree:
        say("other line %s: %s (%s) adds nothing to %s (squash-merged), so %s"
            % (d, short, sha[:9], short_base, short_base))
        return short_base
    # A squash merge after which the base moved on: the branch's whole change (from its merge base)
    # is one commit of the base, the squash commit, with the same patch id.
    squash = squashed_into(d, sha, bsha)
    if squash:
        say("other line %s: %s (%s) was squash-merged as %s in %s, so %s"
            % (d, short, sha[:9], squash[:9], short_base, short_base))
        return short_base
    say("other line %s: same-named branch %s (%s), not yet in %s" % (d, short, sha[:9], short_base))
    return short


def api(repo, path):
    req = urllib.request.Request("https://api.github.com/repos/%s/%s" % (repo, path))
    req.add_header("Accept", "application/vnd.github+json")
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def remote(repo, branch, base):
    if branch == base:
        say("other line %s: %s (the base itself)" % (repo, base))
        return base
    url = "https://github.com/%s.git" % repo
    r = subprocess.run(["git", "ls-remote", "--heads", url, "refs/heads/" + branch],
                       capture_output=True, text=True)
    if r.returncode != 0:
        say("::warning::git ls-remote %s failed (%d); comparing with %s" % (url, r.returncode, base))
        return base
    tip = r.stdout.split()[0] if r.stdout.split() else ""
    if not tip:
        say("other line %s: no branch %s there, so %s" % (repo, branch, base))
        return base
    owner = repo.split("/")[0]
    q = urllib.parse.urlencode({"head": "%s:%s" % (owner, branch), "state": "all", "per_page": 100})
    try:
        pulls = api(repo, "pulls?" + q)
    except (urllib.error.URLError, OSError, ValueError) as e:
        say("::warning::could not list the pull requests of %s:%s (%s); comparing with the same-named "
            "branch as before (tip %s)" % (repo, branch, e, tip[:9]))
        return branch
    live = [p for p in pulls if p.get("state") == "open"]
    if live:
        say("other line %s: %s (tip %s) has open pull request #%s, so %s"
            % (repo, branch, tip[:9], live[0].get("number"), branch))
        return branch
    merged = [p for p in pulls if p.get("merged_at") and (p.get("head") or {}).get("sha") == tip]
    if merged:
        say("other line %s: %s (tip %s) is the head of merged pull request #%s and has no open one: "
            "stale, so %s" % (repo, branch, tip[:9], merged[0].get("number"), base))
        return base
    # No open pull request: a branch that adds nothing to the base (behind it, identical to it, or a
    # merge of the base into an already merged branch, as the item-63 workaround did) is the base.
    try:
        cmp = api(repo, "compare/%s...%s" % (urllib.parse.quote(base, safe=""), urllib.parse.quote(tip, safe="")))
        if cmp.get("status") in ("behind", "identical") or not cmp.get("files"):
            say("other line %s: %s (tip %s) has no open pull request and adds nothing to %s (%s), so %s"
                % (repo, branch, tip[:9], base, cmp.get("status"), base))
            return base
    except (urllib.error.URLError, OSError, ValueError) as e:
        say("::warning::could not compare %s with %s on %s (%s)" % (branch, base, repo, e))
    why = "no pull request yet" if not pulls else "moved since its last pull request"
    say("other line %s: %s (tip %s), %s, so %s" % (repo, branch, tip[:9], why, branch))
    return branch


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--repo", help="OWNER/NAME on GitHub (CI)")
    g.add_argument("--dir", help="a local git repository of the other line")
    ap.add_argument("--branch", required=True)
    ap.add_argument("--base", default="upgrade/vault")
    a = ap.parse_args()
    out = remote(a.repo, a.branch, a.base) if a.repo else local(a.dir, a.branch, a.base)
    if out is None:
        return 1
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
