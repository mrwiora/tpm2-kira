#!/usr/bin/env python3
"""What a batch has to run: the workspace's AGENTS.md, "What to test after a change", for the
changes against a base. It starts nothing, and none of what it names is a final proof
(tools/proof.py is).

    tools/test-affected.py                  # against each project's base branch
    tools/test-affected.py --base REF       # against REF where the project has it
    tools/test-affected.py --since '2026-11-03 09:00'   # against each project's last commit before then: a batch
    tools/test-affected.py --parts          # the parts of tools/proof.py, one per line

Committed changes against the base and what is uncommitted, in each project's own repository.
A submodule's new pin counts as a change to the project it pins. A file no row names is said,
never taken for nothing to do.

tools/test_affected_test.py holds ROWS to AGENTS.md's table.
"""

import argparse
import fnmatch
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE = os.path.dirname(REPO)
PROJECTS = ("tpm2-kira", "assh", "tpm2-kira-vault", "marify", "safearch", "tpm2-verifier", "go-uefi-slim")
# A pin's path in a project (a submodule, a line in a file), and the project it pins.
PINS = {("tpm2-kira", "assh"): "assh", ("tpm2-kira", "go-uefi-slim"): "go-uefi-slim", ("tpm2-kira", "tpm2-verifier"): "tpm2-verifier",
        ("safearch", "assh"): "assh", ("assh", "go-uefi-slim"): "go-uefi-slim", ("tpm2-kira-vault", "tpm2-kira"): "tpm2-kira",
        ("marify", "core.properties"): "tpm2-kira"}
# What of tpm2-kira the boot runs. Everything else of its Go code is the installed system's.
BOOT = ("cmd/tpm2-kira-boot/*", "initramfs/*", "internal/bootclose/*", "internal/bootrun/*", "internal/diskkey/*", "internal/imageplan/*",
        "internal/journal/*", "internal/machineid/*", "internal/memlock/*", "internal/phonegate/*", "internal/screen/*", "internal/sshscreen/*",
        "internal/tpmdev/*", "internal/unixsock/*", "internal/untrusted/*", "internal/vaultkey/*", "internal/wipe/*")
ARGON2 = ("internal/diskkey/combine*", "internal/memlock/*")
DOCS = ("*.md", "docs/*", "LICENSE", "MAINTAINERS", "SECURITY.md")


class Row:
    """A row of AGENTS.md's table, word for word, and what makes a path one of it.
    match(project, path); parts: what tools/proof.py runs for it."""

    def __init__(self, changed, run, match, parts=()):
        self.changed, self.run, self.match, self.parts = changed, run, match, parts


def under(*patterns):
    return lambda path: any(fnmatch.fnmatch(path, p) for p in patterns)


is_docs, is_boot, is_argon2 = under(*DOCS), under(*BOOT), under(*ARGON2)


def kira(rule):
    return lambda project, path: project == "tpm2-kira" and not is_docs(path) and rule(path)


def project_is(name):
    return lambda project, path: project == name and not is_docs(path)


ROWS = (
    Row("Docs only", "nothing", lambda project, path: is_docs(path)),
    Row("Test tools", "the affected step alone (`hibernatetest.py --only STEP`, `vmtest.py --only SECTION`)",
        kira(under("tools/*", "packaging/*", ".github/*", "Makefile"))),
    Row("Installed-system code of tpm2-kira (`control`, `status`, the admin commands)", "`make test-all`",
        kira(lambda path: not under("tools/*", "packaging/*", ".github/*", "Makefile", "core/*")(path) and not is_boot(path)), ("test-all",)),
    Row("tpm2-kira's boot, close or unlock", "`make test-all`; `tools/vmtest.py --fast-kdf`; the affected hibernate steps, from a saved setup",
        kira(is_boot), ("test-all", "machines")),
    Row("Argon2id, or what memory the boot takes", "as above, at the real cost (without `--fast-kdf`), on the affected boots",
        kira(is_argon2), ("test-all", "machines")),
    Row("`tpm2-kira/core/`", "as for the boot; the vault's tests. Marify's `android/scripts/test-emulator.sh` at the end of the batch, after `./pin tpm2-kira`",
        kira(under("core/*")), ("test-all", "machines", "vault", "marify")),
    Row("`assh/`", "its tests (`go test ./...`, swtpm); tpm2-kira's `make test-all` against it (`go.work`); safearch's `tests/run.sh` after `./pin assh`",
        project_is("assh"), ("assh", "test-all", "safearch-run")),
    Row("`tpm2-kira-vault/`", "its tests; the vault steps of `tools/vmtest.py` at the end of the batch",
        project_is("tpm2-kira-vault"), ("vault", "machines")),
    Row("`go-uefi-slim/`", "its tests (the immutable test as root on a VM); aSSH's and tpm2-kira's suites after `./pin go-uefi-slim`",
        project_is("go-uefi-slim"), ("go-uefi-slim", "assh", "test-all")),
    Row("`tpm2-verifier/`", "its tests; `core`'s and the vault's after `./pin tpm2-verifier`",
        project_is("tpm2-verifier"), ("tpm2-verifier", "test-all", "vault")),
    Row("`safearch/`", "`tests/run.sh`; `tests/vm.sh` at the end of the batch, when the boot changed",
        project_is("safearch"), ("safearch-run",)),
)


def rows_of(project, path):
    """The rows a changed path falls under (the Argon2id row comes on top of the boot's);
    none when no row names it."""
    pinned = PINS.get((project, path))
    if pinned:
        # A pin moved: what the pinned project's row asks, for any of its code.
        return rows_of(pinned, "core/pin" if pinned == "tpm2-kira" else "pin")
    return [r for r in ROWS if r.match(project, path)]


def git(project_dir, *args):
    p = subprocess.run(["git", "-C", project_dir, *args], capture_output=True, text=True)
    return p.returncode, p.stdout


def base_of(project_dir, wanted, since=None):
    """The ref to compare a project against: its last commit before since; --base where it
    has it; else its base branch."""
    if since:
        rc, out = git(project_dir, "rev-list", "-1", "--before=" + since, "HEAD")
        if rc == 0 and out.strip():
            return out.strip()
    for ref in ([wanted] if wanted else []) + ["origin/HEAD", "origin/dev", "dev", "origin/main", "main", "origin/master", "master"]:
        if git(project_dir, "rev-parse", "--verify", "-q", ref + "^{commit}")[0] == 0:
            return ref
    return None


def changed_paths(project_dir, wanted, since=None):
    """The paths a project changed against its base, committed or not. The base, and them."""
    base = base_of(project_dir, wanted, since)
    paths = set()
    if base:
        rc, mb = git(project_dir, "merge-base", base, "HEAD")
        if rc == 0:
            paths |= set(git(project_dir, "diff", "--name-only", mb.strip())[1].split("\n"))
    for line in git(project_dir, "status", "--porcelain")[1].split("\n"):
        if line[3:]:
            paths.add(line[3:].split(" -> ")[-1].strip('"'))
    paths.discard("")
    return base, sorted(paths)


def affected(wanted=None, workspace=WORKSPACE, since=None):
    """What the changes ask for: (rows in the table's order, the paths no row names, the
    bases per project, the number of paths per row)."""
    hit, unnamed, bases = {}, [], {}
    for project in PROJECTS:
        d = os.path.join(workspace, project)
        if not os.path.isdir(d):
            continue
        base, paths = changed_paths(d, wanted, since)
        bases[project] = base
        for path in paths:
            rows = rows_of(project, path)
            if not rows:
                unnamed.append(f"{project}/{path}")
            for r in rows:
                hit.setdefault(r.changed, []).append(f"{project}/{path}")
    return [r for r in ROWS if r.changed in hit], unnamed, bases, hit


def parts_of(rows):
    """The parts of tools/proof.py the rows name, each once."""
    out = []
    for r in rows:
        out += [p for p in r.parts if p not in out]
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", help="the ref to compare against, where a project has it (default: its base branch)")
    ap.add_argument("--since", help="against each project's last commit before this time (git's --before)")
    ap.add_argument("--parts", action="store_true", help="the parts of tools/proof.py, one per line")
    args = ap.parse_args()
    rows, unnamed, bases, hit = affected(args.base, since=args.since)
    if args.parts:
        print("\n".join(parts_of(rows)))
        return 0
    for project, base in bases.items():
        if base is None:
            print(f"{project}: no base found: only what is uncommitted counts (--base REF)")
    if not rows and not unnamed:
        print("nothing changed against the bases")
    for r in rows:
        print(f"{r.changed} ({len(hit[r.changed])} path(s)):\n    {r.run}")
    for path in unnamed:
        print(f"no row of the table names {path}: decide by hand")
    print("None of this is a final proof: tools/proof.py is.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
