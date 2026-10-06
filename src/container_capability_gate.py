"""Prepare a narrowly scoped OCI process capability policy for an owned bundle.

This tool only guards the OCI JSON it emits. It cannot prevent a caller from
invoking a runtime directly with a different bundle or an unchecked exec spec.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re
import subprocess
import tempfile


CAPABILITY = re.compile(r"CAP_[A-Z0-9_]+\Z")
SETS = ("bounding", "effective", "permitted", "inheritable", "ambient")
REQUIRED_NAMESPACES = frozenset(("pid", "mount", "network", "ipc", "uts"))
KNOWN_CAPABILITIES = frozenset("""
CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID CAP_KILL
CAP_SETGID CAP_SETUID CAP_SETPCAP CAP_LINUX_IMMUTABLE CAP_NET_BIND_SERVICE
CAP_NET_BROADCAST CAP_NET_ADMIN CAP_NET_RAW CAP_IPC_LOCK CAP_IPC_OWNER
CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_CHROOT CAP_SYS_PTRACE CAP_SYS_PACCT
CAP_SYS_ADMIN CAP_SYS_BOOT CAP_SYS_NICE CAP_SYS_RESOURCE CAP_SYS_TIME
CAP_SYS_TTY_CONFIG CAP_MKNOD CAP_LEASE CAP_AUDIT_WRITE CAP_AUDIT_CONTROL
CAP_SETFCAP CAP_MAC_OVERRIDE CAP_MAC_ADMIN CAP_SYSLOG CAP_WAKE_ALARM
CAP_BLOCK_SUSPEND CAP_AUDIT_READ CAP_PERFMON CAP_BPF CAP_CHECKPOINT_RESTORE
""".split())


class PolicyError(ValueError):
    pass


def parse_json(value: str) -> object:
    """Reject duplicate keys and nonfinite numbers before policy comparison."""
    def unique_object(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for name, item in pairs:
            if name in result:
                raise PolicyError(f"duplicate JSON key: {name}")
            result[name] = item
        return result

    def reject_constant(value: str) -> object:
        raise PolicyError(f"nonfinite JSON value: {value}")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise PolicyError(f"nonfinite JSON number: {value}")
        return parsed

    return json.loads(value, object_pairs_hook=unique_object,
                      parse_constant=reject_constant, parse_float=finite_float)


def _json_copy(value: object) -> object:
    try:
        return json.loads(json.dumps(value, allow_nan=False))
    except (TypeError, ValueError) as error:
        raise PolicyError(f"invalid JSON value: {error}") from error


def _object(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise PolicyError(f"{label} must be an object")
    return value


def _capabilities(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or
                                          not CAPABILITY.fullmatch(item) for item in value):
        raise PolicyError(f"{label} must be a list of capability names")
    if len(value) != len(set(value)):
        raise PolicyError(f"{label} contains duplicate capabilities")
    if not set(value).issubset(KNOWN_CAPABILITIES):
        raise PolicyError(f"{label} contains an unknown capability")
    return sorted(value)


def prepare(spec: object, allowed: object) -> dict:
    """Return an OCI spec whose five process sets are restricted to allowlist."""
    spec = _object(spec, "OCI spec")
    process = _object(spec.get("process"), "process")
    linux = _object(spec.get("linux"), "linux")
    _object(spec.get("root"), "root")
    allowed = _capabilities(allowed, "allowed")
    if not isinstance(spec.get("ociVersion"), str):
        raise PolicyError("ociVersion is required")
    if process.get("terminal") is not False:
        raise PolicyError("nonterminal process required for recorded execution")
    if not isinstance(process.get("args"), list) or not process["args"]:
        raise PolicyError("process args are required")
    namespaces = linux.get("namespaces")
    if not isinstance(namespaces, list):
        raise PolicyError("linux.namespaces must be a list")
    types = []
    for namespace in namespaces:
        namespace = _object(namespace, "namespace")
        kind = namespace.get("type")
        if not isinstance(kind, str) or namespace.get("path"):
            raise PolicyError("namespaces must be newly created without host paths")
        types.append(kind)
    if len(types) != len(set(types)) or not REQUIRED_NAMESPACES.issubset(types):
        raise PolicyError("required isolated namespaces are absent or duplicated")
    existing = _object(process.get("capabilities"), "process.capabilities")
    requested = {}
    for name in SETS:
        given = _capabilities(existing.get(name, []), name)
        if not set(given).issubset(allowed):
            raise PolicyError(f"{name} requests capability outside policy")
        requested[name] = given
    if requested["bounding"] != requested["effective"] or \
            requested["bounding"] != requested["permitted"] or \
            requested["inheritable"] or requested["ambient"]:
        raise PolicyError("creation capability sets must match and inheritance must be empty")
    if process.get("noNewPrivileges") is not True:
        raise PolicyError("noNewPrivileges must be true")
    prepared = _json_copy(spec)
    prepared["process"]["capabilities"] = {
        "bounding": requested["bounding"], "effective": requested["effective"],
        "permitted": requested["permitted"],
        "inheritable": [], "ambient": [],
    }
    return prepared


def check_exec(process: object, allowed: object) -> dict:
    """Reject any runc exec process spec that requests more than allowlist."""
    process = _object(process, "exec process")
    allowed = _capabilities(allowed, "allowed")
    if process.get("noNewPrivileges") is not True:
        raise PolicyError("exec noNewPrivileges must be true")
    if not isinstance(process.get("args"), list) or not process["args"] or \
            any(not isinstance(arg, str) for arg in process["args"]):
        raise PolicyError("exec args must be a nonempty string list")
    caps = _object(process.get("capabilities"), "exec capabilities")
    requested = {}
    for name in SETS:
        actual = _capabilities(caps.get(name, []), f"exec {name}")
        if not set(actual).issubset(allowed):
            raise PolicyError(f"exec {name} exceeds policy")
        requested[name] = actual
    if requested["bounding"] != requested["effective"] or \
            requested["bounding"] != requested["permitted"] or \
            requested["inheritable"] or requested["ambient"]:
        raise PolicyError("exec capability sets must match and inheritance must be empty")
    checked = _json_copy(process)
    checked["capabilities"] = {name: requested[name] for name in SETS}
    return checked


def run_checked_exec(process: object, allowed: object, runtime: Path,
                     runtime_root: Path, container_id: str, build_root: Path) -> int:
    """Launch runc exec using a checked private copy of the process spec."""
    checked = check_exec(process, allowed)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", container_id):
        raise PolicyError("invalid container ID")
    if build_root.resolve().name != "Build":
        raise PolicyError("temporary spec directory must be Build")
    with tempfile.TemporaryDirectory(prefix="capability-exec-", dir=build_root) as temp:
        spec_path = Path(temp) / "process.json"
        spec_path.write_text(json.dumps(checked, sort_keys=True, indent=2,
                                        allow_nan=False) + "\n")
        return subprocess.run([str(runtime), "--root", str(runtime_root), "exec",
                               "--process", str(spec_path), container_id],
                              check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "check-exec", "run-exec"))
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--id")
    parser.add_argument("--build-root", type=Path)
    args = parser.parse_args()
    try:
        policy = _object(parse_json(args.policy.read_text()), "policy")
        allowed = policy.get("allowed_capabilities")
        value = parse_json(args.input.read_text())
        if args.mode == "prepare":
            if args.output is None:
                parser.error("--output is required for prepare")
            output = prepare(value, allowed)
            args.output.write_text(json.dumps(output, sort_keys=True, indent=2,
                                              allow_nan=False) + "\n")
            return 0
        if args.mode == "check-exec":
            check_exec(value, allowed)
            print("EXEC_POLICY=PASS")
            return 0
        if any(item is None for item in (args.runtime, args.runtime_root, args.id, args.build_root)):
            parser.error("run-exec requires --runtime, --runtime-root, --id and --build-root")
        return run_checked_exec(value, allowed, args.runtime, args.runtime_root,
                                args.id, args.build_root)
    except (PolicyError, json.JSONDecodeError) as error:
        parser.exit(2, f"POLICY_REJECT: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
