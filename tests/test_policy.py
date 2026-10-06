import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.container_capability_gate import (PolicyError, check_exec, parse_json,
                                           prepare, run_checked_exec, trusted_private_root,
                                           trusted_creation_spec, trusted_runtime,
                                           trusted_runtime_root)


def spec(caps=()):
    names = list(caps)
    return {
        "ociVersion": "1.3.0",
        "process": {"terminal": False, "args": ["/bin/live-probe", "deny"],
                    "noNewPrivileges": True,
                    "capabilities": {name: names for name in
                                     ("bounding", "effective", "permitted")}},
        "root": {"path": "rootfs"},
        "linux": {"namespaces": [{"type": name} for name in
                                ("pid", "mount", "network", "ipc", "uts")]},
    }


class PolicyTests(unittest.TestCase):
    def test_denied_capability_in_any_set(self):
        for name in ("bounding", "effective", "permitted", "inheritable", "ambient"):
            with self.subTest(name=name):
                value = spec()
                value["process"]["capabilities"][name] = ["CAP_NET_RAW"]
                with self.assertRaises(PolicyError):
                    prepare(value, [])

    def test_explicit_whitelist_and_empty_inheritable_ambient(self):
        result = prepare(spec(["CAP_NET_RAW"]), ["CAP_NET_RAW"])
        self.assertEqual(result["process"]["capabilities"]["effective"], ["CAP_NET_RAW"])
        self.assertEqual(result["process"]["capabilities"]["ambient"], [])

    def test_allowlist_never_adds_unrequested_capability(self):
        result = prepare(spec(), ["CAP_NET_RAW"])
        self.assertEqual(result["process"]["capabilities"]["effective"], [])
        value = spec(["CAP_NET_RAW"])
        value["process"]["capabilities"]["effective"] = []
        with self.assertRaises(PolicyError):
            prepare(value, ["CAP_NET_RAW"])

    def test_namespace_host_path_and_nnp_rejected(self):
        value = spec()
        value["linux"]["namespaces"][0]["path"] = "/proc/1/ns/pid"
        with self.assertRaises(PolicyError):
            prepare(value, [])
        value = spec()
        value["process"]["noNewPrivileges"] = False
        with self.assertRaises(PolicyError):
            prepare(value, [])

    def test_exec_cannot_regain_capability(self):
        process = {"noNewPrivileges": True, "args": ["/bin/live-probe", "deny", "exec"],
                   "capabilities": {"bounding": [], "effective": ["CAP_NET_RAW"],
                                    "permitted": [], "inheritable": [], "ambient": []}}
        with self.assertRaises(PolicyError):
            check_exec(process, [], [])
        process = copy.deepcopy(process)
        process["capabilities"]["effective"] = []
        checked = check_exec(process, [], [])
        self.assertEqual(checked, process)
        self.assertIsNot(checked, process)

    def test_exec_missing_sets_are_emitted_as_explicit_empty_lists(self):
        process = {"noNewPrivileges": True, "args": ["/bin/live-probe", "deny", "exec"],
                   "capabilities": {}}
        checked = check_exec(process, [], [])
        self.assertEqual(set(checked["capabilities"]),
                         {"bounding", "effective", "permitted", "inheritable", "ambient"})
        self.assertTrue(all(value == [] for value in checked["capabilities"].values()))

    def test_rejected_exec_never_reaches_runtime(self):
        process = {"noNewPrivileges": True, "args": ["/bin/live-probe", "allow", "exec"],
                   "capabilities": {name: ["CAP_NET_RAW"] for name in
                                    ("bounding", "effective", "permitted")}}
        with patch("src.container_capability_gate.subprocess.run") as runtime:
            with self.assertRaises(PolicyError):
                run_checked_exec(process, [], Path("/tmp/ccdg/approved/held/config.json"),
                                 Path("/tmp/ccdg/runc"), Path("/tmp/ccdg/runtime-state"),
                                 "held", Path("/tmp/ccdg"))
            runtime.assert_not_called()

    def test_exec_cannot_regain_capability_omitted_at_creation(self):
        process = {"noNewPrivileges": True, "args": ["/bin/live-probe", "allow", "exec"],
                   "capabilities": {name: ["CAP_NET_RAW"] for name in
                                    ("bounding", "effective", "permitted")}}
        with self.assertRaises(PolicyError):
            check_exec(process, ["CAP_NET_RAW"], [])
        self.assertEqual(check_exec(process, ["CAP_NET_RAW"], ["CAP_NET_RAW"])
                         ["capabilities"]["effective"], ["CAP_NET_RAW"])

    def test_untrusted_private_parent_is_rejected_before_exec(self):
        process = {"noNewPrivileges": True, "args": ["/bin/live-probe", "deny", "exec"],
                   "capabilities": {}}
        with tempfile.TemporaryDirectory(dir="/tmp") as directory, \
             patch("src.container_capability_gate.os.geteuid", return_value=0), \
             patch("src.container_capability_gate.subprocess.run") as runtime:
            private_root = Path(directory)
            with self.assertRaises(PolicyError):
                run_checked_exec(process, [], private_root / "approved/held/config.json",
                                 private_root / "runc", private_root / "runtime-state",
                                 "held", private_root)
            runtime.assert_not_called()
        with self.assertRaises(PolicyError):
            trusted_private_root(Path("ccdg"))

    def test_runtime_and_state_must_be_inside_private_root(self):
        private_root = Path("/var/lib/container-capability-gate")
        with self.assertRaises(PolicyError):
            trusted_runtime(Path("/tmp/fake-runc"), private_root)
        with self.assertRaises(PolicyError):
            trusted_runtime_root(Path("/tmp/runc-state"), private_root)

    def test_creation_record_must_match_container_id(self):
        with self.assertRaises(PolicyError):
            trusted_creation_spec(Path("/tmp/ccdg/approved/other/config.json"),
                                  Path("/tmp/ccdg"), "held")

    def test_checked_exec_passes_normalized_private_file_to_runtime(self):
        process = {"noNewPrivileges": True, "args": ["/bin/live-probe", "deny", "exec"],
                   "capabilities": {}}
        with tempfile.TemporaryDirectory() as directory:
            private_root = Path(directory)
            runtime = private_root / "runc"
            state = private_root / "runtime-state"
            record = private_root / "approved/held/config.json"
            seen = {}

            def fake_runtime(command, check):
                self.assertEqual(command[:4], [str(runtime), "--root", str(state), "exec"])
                checked_path = Path(command[5])
                self.assertEqual(command[4], "--process")
                self.assertEqual(command[6], "held")
                self.assertEqual(os.stat(checked_path).st_mode & 0o777, 0o600)
                seen["capabilities"] = json.loads(checked_path.read_text())["capabilities"]
                return type("Result", (), {"returncode": 0})()

            with patch("src.container_capability_gate.trusted_private_root", return_value=private_root), \
                 patch("src.container_capability_gate.trusted_runtime", return_value=runtime), \
                 patch("src.container_capability_gate.trusted_runtime_root", return_value=state), \
                 patch("src.container_capability_gate.trusted_creation_spec", return_value=spec()), \
                 patch("src.container_capability_gate.subprocess.run", side_effect=fake_runtime):
                self.assertEqual(run_checked_exec(process, [], record, runtime, state,
                                                  "held", private_root), 0)
            self.assertEqual(seen["capabilities"], {name: [] for name in
                             ("bounding", "effective", "permitted", "inheritable", "ambient")})

    def test_duplicate_json_key_is_rejected(self):
        with self.assertRaises(PolicyError):
            parse_json('{"allowed_capabilities":[],"allowed_capabilities":["CAP_NET_RAW"]}')
        with self.assertRaises(PolicyError):
            parse_json('{"allowed_capabilities":[NaN]}')

    def test_overflowed_json_number_and_library_output_are_rejected(self):
        for literal in ("1e999", "-1e999", "Infinity"):
            with self.subTest(literal=literal), self.assertRaises(PolicyError):
                parse_json('{"extra":' + literal + '}')
        value = spec()
        value["extra"] = float("inf")
        with self.assertRaises(PolicyError):
            prepare(value, [])
        process = {"noNewPrivileges": True, "args": ["/bin/live-probe", "deny", "exec"],
                   "capabilities": {}, "extra": float("nan")}
        with self.assertRaises(PolicyError):
            check_exec(process, [], [])


if __name__ == "__main__":
    unittest.main()
