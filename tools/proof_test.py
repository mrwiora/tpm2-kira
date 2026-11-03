#!/usr/bin/env python3
"""tools/proof.py's limit and budgets, on parts that only sleep; the scenario table's sums."""

import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, file))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


proof = load("proof", "proof.py")
vmtest = load("vmtest", "vmtest.py")


def sleeper(name, seconds):
    return proof.Part(name, ["sleep", str(seconds)], "/", memory=1)


def write_scenarios(run_dir, machine, done):
    d = os.path.join(run_dir, "machines", machine)
    os.makedirs(d)
    with open(os.path.join(d, "scenarios.json"), "w") as f:
        json.dump(done, f)


class Limit(unittest.TestCase):
    def test_a_run_over_the_limit_stops_fails_and_names_the_scenario(self):
        with tempfile.TemporaryDirectory() as run_dir:
            write_scenarios(run_dir, "arch", [{"name": "setup", "budget": 2, "seconds": 3.0, "result": "ok"},
                                              {"name": "typed-boot", "budget": 47, "seconds": None, "result": "running"}])
            parts = [sleeper("long", 60), sleeper("short", 0), sleeper("waits", 0)]
            parts[2].memory = 10
            start = time.monotonic()
            proof.run_parts(parts, run_dir, 2, start, limit=0.5)
            took = time.monotonic() - start
            self.assertLess(took, 10, "the limit did not stop the part")
            text, ok = proof.report(parts, took, [], run_dir, limit=0, proof_wall=took)
            self.assertFalse(ok)
            self.assertIn("OVER THE LIMIT", text)
            self.assertIn("arch setup 3 s of 2", text)
            self.assertIn("stopped in: arch typed-boot (budget 47 s)", text)
            self.assertIn("not started: the limit", text)

    def test_over_a_budget_within_the_limit_is_said_and_no_failure(self):
        with tempfile.TemporaryDirectory() as run_dir:
            write_scenarios(run_dir, "debian", [{"name": "revoked", "budget": 59, "seconds": 61.0, "result": "ok"}])
            parts = [sleeper("short", 0)]
            proof.run_parts(parts, run_dir, 2, time.monotonic(), limit=60)
            text, ok = proof.report(parts, 1, [], run_dir, limit=960, proof_wall=800, target=900)
            self.assertTrue(ok, text)
            self.assertIn("over budget, within the target: debian revoked 61 s of 59", text)
            self.assertIn("61 / 59 OVER", text)

    def test_over_the_target_within_the_limit_passes_and_names_what_went_over(self):
        with tempfile.TemporaryDirectory() as run_dir:
            write_scenarios(run_dir, "debian", [{"name": "revoked", "budget": 59, "seconds": 61.0, "result": "ok"}])
            parts = [sleeper("short", 0)]
            proof.run_parts(parts, run_dir, 2, time.monotonic(), limit=60)
            text, ok = proof.report(parts, 1, [], run_dir, limit=960, proof_wall=930, target=900)
            self.assertTrue(ok, text)
            self.assertIn("OVER THE TARGET, within the limit: 930 s of 900", text)
            self.assertIn("debian revoked 61 s of 59", text)

    def test_past_the_limit_it_fails(self):
        with tempfile.TemporaryDirectory() as run_dir:
            parts = [sleeper("short", 0)]
            proof.run_parts(parts, run_dir, 2, time.monotonic(), limit=60)
            text, ok = proof.report(parts, 1, [], run_dir, limit=960, proof_wall=961, target=900)
            self.assertFalse(ok, text)
            self.assertIn("OVER THE LIMIT", text)

    def test_a_part_that_fails_fails_the_run(self):
        with tempfile.TemporaryDirectory() as run_dir:
            parts = [proof.Part("no", ["false"], "/", memory=1)]
            proof.run_parts(parts, run_dir, 2, time.monotonic())
            _, ok = proof.report(parts, 1, [], run_dir)
            self.assertFalse(ok)


class AfterTheSetups(unittest.TestCase):
    def machines_and_tests(self):
        machines = proof.Part("machines", ["sleep", "60"], "/", machines=True, memory=1)
        tests = sleeper("tests", 0)
        tests.after_setup = True
        return machines, tests

    def test_a_part_waits_for_the_setups_of_both_machines(self):
        with tempfile.TemporaryDirectory() as run_dir:
            machines, tests = self.machines_and_tests()
            self.assertTrue(proof.held(tests, [machines, tests], run_dir))
            write_scenarios(run_dir, "arch", [{"name": "setup", "budget": 1, "seconds": 1.0, "result": "ok"}])
            write_scenarios(run_dir, "debian", [{"name": "setup", "budget": 1, "seconds": None, "result": "running"}])
            self.assertTrue(proof.held(tests, [machines, tests], run_dir))
            os.remove(os.path.join(run_dir, "machines", "debian", "scenarios.json"))
            with open(os.path.join(run_dir, "machines", "debian", "scenarios.json"), "w") as f:
                json.dump([{"name": "setup", "budget": 1, "seconds": 1.0, "result": "FAILED"}], f)
            self.assertFalse(proof.held(tests, [machines, tests], run_dir))

    def test_machines_that_end_without_a_setup_hold_nothing(self):
        with tempfile.TemporaryDirectory() as run_dir:
            machines, tests = self.machines_and_tests()
            machines.ok = False
            self.assertFalse(proof.held(tests, [machines, tests], run_dir))

    def test_without_machines_nothing_is_held(self):
        with tempfile.TemporaryDirectory() as run_dir:
            _, tests = self.machines_and_tests()
            self.assertFalse(proof.held(tests, [tests], run_dir))


class Scenarios(unittest.TestCase):
    def test_every_scenario_is_in_the_proof_or_under_all(self):
        proof_names = vmtest.scenarios_of()
        self.assertEqual(proof_names, [s.name for s in vmtest.SCENARIOS if s.budget])
        self.assertEqual(vmtest.scenarios_of(everything=True), [s.name for s in vmtest.SCENARIOS])
        self.assertIn("silent-tpm", proof_names)
        self.assertIn("V3", vmtest.scenarios_of(everything=True))
        self.assertNotIn("V3", proof_names)

    def test_only_takes_what_a_scenario_needs(self):
        self.assertEqual(vmtest.scenarios_of(["revoked"]), ["secure-boot", "tpm-salt", "vault-pepper", "revoked"])
        self.assertEqual(vmtest.scenarios_of(["setup"]), ["setup"])

    def test_the_budgets_fit_the_limit(self):
        for distro in ("arch", "debian"):
            total = sum((s.budget or {}).get(distro) or 0 for s in vmtest.SCENARIOS if s.distro in (None, distro))
            self.assertLessEqual(total, proof.TARGET, distro)

    def test_a_scenario_on_one_distribution_has_a_budget_for_it_alone(self):
        for s in vmtest.SCENARIOS:
            if s.budget and s.distro:
                other = "debian" if s.distro == "arch" else "arch"
                self.assertIsNone(s.budget[other], s.name)


if __name__ == "__main__":
    unittest.main()
