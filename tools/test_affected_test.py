#!/usr/bin/env python3
"""tools/test-affected.py against the workspace's AGENTS.md: its table and the helper's can't
drift apart. Outside the workspace there is no table to hold it to, and it says so."""

import importlib.util
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
AGENTS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "AGENTS.md")


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, file))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


affected = load("test_affected", "test-affected.py")
proof = load("proof", "proof.py")


def agents_table():
    """AGENTS.md's table under "What to test after a change": (Changed, Run) per row."""
    with open(AGENTS) as f:
        section = f.read().split("### What to test after a change", 1)[1]
    rows = [[c.strip() for c in l.strip().strip("|").split(" | ")] for l in section.splitlines() if l.startswith("|")]
    return [tuple(r) for r in rows[2:]]


class Table(unittest.TestCase):
    @unittest.skipUnless(os.path.exists(AGENTS), "not in the workspace: no AGENTS.md to hold the table to")
    def test_rows_are_the_agents_table_word_for_word(self):
        self.assertEqual(agents_table(), [(r.changed, r.run) for r in affected.ROWS])

    def test_every_part_is_a_part_of_the_proof(self):
        known = proof.parts_table("/nonexistent")
        for r in affected.ROWS:
            for part in r.parts:
                self.assertIn(part, known, r.changed)


class Paths(unittest.TestCase):
    def rows(self, project, path):
        return [r.changed for r in affected.rows_of(project, path)]

    def test_paths(self):
        boot, installed, core = "tpm2-kira's boot, close or unlock", "Installed-system code of tpm2-kira (`control`, `status`, the admin commands)", "`tpm2-kira/core/`"
        argon = "Argon2id, or what memory the boot takes"
        for project, path, want in (
            ("tpm2-kira", "docs/TESTING.md", ["Docs only"]),
            ("assh", "README.md", ["Docs only"]),
            ("tpm2-kira", "core/README.md", ["Docs only"]),
            ("tpm2-kira", "tools/vmtest.py", ["Test tools"]),
            ("tpm2-kira", "internal/admin/control.go", [installed]),
            ("tpm2-kira", "main.go", [installed]),
            ("tpm2-kira", "initramfs/systemd/tpm2-kira.service", [boot]),
            ("tpm2-kira", "internal/bootclose/close.go", [boot]),
            ("tpm2-kira", "internal/diskkey/combine.go", [boot, argon]),
            ("tpm2-kira", "core/attest/quote.go", [core]),
            ("assh", "server/server.go", ["`assh/`"]),
            ("tpm2-kira", "assh", ["`assh/`"]),
            ("safearch", "assh", ["`assh/`"]),
            ("tpm2-kira", "go-uefi-slim", ["`go-uefi-slim/`"]),
            ("tpm2-kira", "tpm2-verifier", ["`tpm2-verifier/`"]),
            ("tpm2-kira-vault", "tpm2-kira", [core]),
            ("tpm2-kira-vault", "main.go", ["`tpm2-kira-vault/`"]),
            ("safearch", "build.sh", ["`safearch/`"]),
            ("go-uefi-slim", "uki/uki.go", ["`go-uefi-slim/`"]),
            ("tpm2-verifier", "ekroots/roots.go", ["`tpm2-verifier/`"]),
            ("marify", "android/app/x.kt", []),
            ("marify", "core.properties", [core]),
        ):
            self.assertEqual(self.rows(project, path), want, f"{project}/{path}")

    def test_parts_each_once_in_the_tables_order(self):
        rows = [r for r in affected.ROWS if r.changed in ("`tpm2-kira/core/`", "`assh/`")]
        self.assertEqual(affected.parts_of(rows), ["test-all", "machines", "vault", "marify", "assh", "safearch-run"])


if __name__ == "__main__":
    unittest.main()
