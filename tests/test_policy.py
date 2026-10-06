import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.container_capability_gate import PolicyError, check_exec, parse_json, prepare, run_checked_exec


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
            check_exec(process, [])
        process = copy.deepcopy(process)
        process["capabilities"]["effective"] = []
        checked = check_exec(process, [])
        self.assertEqual(checked, process)
        self.assertIsNot(checked, process)

    def test_exec_missing_sets_are_emitted_as_explicit_empty_lists(self):
        process = {"noNewPrivileges": True, "args": ["/bin/live-probe", "deny", "exec"],
                   "capabilities": {}}
        checked = check_exec(process, [])
        self.assertEqual(set(checked["capabilities"]),
                         {"bounding", "effective", "permitted", "inheritable", "ambient"})
        self.assertTrue(all(value == [] for value in checked["capabilities"].values()))

    def test_rejected_exec_never_reaches_runtime(self):
        process = {"noNewPrivileges": True, "args": ["/bin/live-probe", "allow", "exec"],
                   "capabilities": {name: ["CAP_NET_RAW"] for name in
                                    ("bounding", "effective", "permitted")}}
        with patch("src.container_capability_gate.subprocess.run") as runtime:
            with self.assertRaises(PolicyError):
                run_checked_exec(process, [], Path("/usr/bin/runc"), Path("/run/runc"),
                                 "held", Path("/tmp/Build"))
            runtime.assert_not_called()

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
            check_exec(process, [])


if __name__ == "__main__":
    unittest.main()
