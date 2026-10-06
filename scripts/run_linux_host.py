"""Exercise owned OCI bundles on a native x86_64 Linux host with pinned runc."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


PROJECT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(PROJECT))
from src.container_capability_gate import check_exec, prepare, trusted_private_root  # noqa: E402


RUNC_SHA256 = "599f6f94ff8c5057241eff0d54c3c74f95c34935b6457b33fe545defc61e9488"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def spec(raw: bool, args: list[str]) -> dict:
    caps = ["CAP_NET_RAW"] if raw else []
    return {
        "ociVersion": "1.3.0",
        "process": {"terminal": False, "user": {"uid": 0, "gid": 0},
                    "args": args, "env": ["PATH=/bin"], "cwd": "/",
                    "noNewPrivileges": True,
                    "capabilities": {"bounding": caps, "effective": caps, "permitted": caps,
                                     "inheritable": [], "ambient": []}},
        "root": {"path": "rootfs", "readonly": False},
        "hostname": "capability-ci",
        "mounts": [{"destination": "/proc", "type": "proc", "source": "proc"},
                   {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
                    "options": ["nosuid", "mode=755"]}],
        "linux": {"namespaces": [{"type": name} for name in
                                ("pid", "mount", "network", "ipc", "uts")]},
    }


def cap_probe_rows(output: str, expected: int, phases: tuple[str, str]) -> list[dict]:
    pattern = (r"^PHASE=(INIT|CHILD_EXEC|OCI_EXEC|OCI_EXEC_CHILD) CapEff=([0-9a-f]{16}) "
               r"CapPrm=([0-9a-f]{16}) CapBnd=([0-9a-f]{16}) CapInh=([0-9a-f]{16}) "
               r"CapAmb=([0-9a-f]{16}) RAW_SOCKET=(ALLOW|DENY) errno=(\d+)$")
    rows = re.findall(pattern, output, re.M)
    if len(rows) != 2 or output.count("PROBE_RESULT=PASS") != 1:
        raise AssertionError("missing complete process/child probe")
    result = []
    for row, phase in zip(rows, phases):
        seen_phase, eff, prm, bnd, inh, amb, operation, error = row
        if seen_phase != phase or any(int(value, 16) != expected for value in
                                      (eff, prm, bnd)) or int(inh, 16) != 0 or \
                int(amb, 16) != 0 or operation != ("ALLOW" if expected else "DENY") or \
                int(error) != (0 if expected else 1):
            raise AssertionError(f"unexpected capability or raw socket result in {phase}")
        result.append({"phase": phase, "cap_eff": eff, "cap_prm": prm,
                       "cap_bnd": bnd, "cap_inh": inh, "cap_amb": amb,
                       "raw_socket": operation, "errno": int(error)})
    return result


def command(runtime: Path, state: Path, *arguments: str,
            timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run([str(runtime), "--root", str(state), *arguments],
                          input=b"", capture_output=True, timeout=timeout, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--run-id")
    args = parser.parse_args()
    build = args.build_root.resolve()
    if build.name != "Build":
        parser.error("--build-root must be the workspace Build directory")
    run_id = args.run_id or datetime.now(timezone.utc).strftime("native-%Y%m%dT%H%M%SZ")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", run_id):
        parser.error("invalid run ID")
    run_dir = build / "验证/ContainerCapabilityDropGate-20261006" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    receipt = {"status": "OPEN", "created_utc": datetime.now(timezone.utc).isoformat(),
               "run_id": run_id, "platform": platform.platform(), "source_root": str(PROJECT),
               "run_dir": str(run_dir)}
    try:
        if sys.platform != "linux" or platform.machine() not in ("x86_64", "amd64"):
            raise RuntimeError("native Linux x86_64 host required")
        if os.geteuid() != 0:
            raise RuntimeError("root required to create the isolated OCI test containers")
        runtime = args.runtime.resolve()
        if not runtime.is_file() or sha256(runtime) != RUNC_SHA256:
            raise RuntimeError("missing or changed official runc v1.5.2 amd64 binary")
        receipt["runtime_sha256"] = RUNC_SHA256
        if " - cgroup2 " not in Path("/proc/self/mountinfo").read_text():
            raise RuntimeError("cgroup v2 is not mounted")
        host_status = Path("/proc/self/status").read_text()
        bounding = re.search(r"^CapBnd:\s*([0-9a-fA-F]+)$", host_status, re.M)
        if not bounding or not (int(bounding.group(1), 16) & 0x2000):
            raise RuntimeError("host root lacks CAP_NET_RAW for the positive control")
        receipt["host_cap_bnd"] = bounding.group(1)
        probe = run_dir / "live-probe"
        with (run_dir / "probe.compile.log").open("w") as stream:
            subprocess.run(["gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                            str(PROJECT / "tests/live_probe.c"), "-o", str(probe)],
                           check=True, stdout=stream, stderr=subprocess.STDOUT)
        receipt["probe_sha256"] = sha256(probe)
        receipt["source_sha256"] = {str(path.relative_to(PROJECT)): sha256(path) for path in (
            PROJECT / "src/container_capability_gate.py", PROJECT / "tests/live_probe.c",
            Path(__file__))}
        private_parent = Path("/var/lib/container-capability-gate-tests")
        private_parent.mkdir(mode=0o700, exist_ok=True)
        trusted_private_root(private_parent)
        private_root = private_parent / run_id
        private_root.mkdir(mode=0o700, exist_ok=False)
        receipt["private_test_root"] = str(private_root)
        protected_runtime = private_root / "runc"
        shutil.copy2(runtime, protected_runtime)
        protected_runtime.chmod(0o700)
        state = private_root / "runtime-state"
        state.mkdir(mode=0o700, exist_ok=True)
        state.chmod(0o700)
        cases = [("baseline", True, "allow"), ("guard", False, "deny"),
                 ("allow", True, "allow"), ("held", False, "hold")]
        bundles = {}
        for name, raw, mode in cases:
            bundle = run_dir / name
            for relative in ("rootfs/bin", "rootfs/proc", "rootfs/dev"):
                (bundle / relative).mkdir(parents=True, exist_ok=True)
            shutil.copy2(probe, bundle / "rootfs/bin/live-probe")
            template = spec(raw, ["/bin/live-probe", mode])
            output = template if name == "baseline" else prepare(template, ["CAP_NET_RAW"] if raw else [])
            (bundle / "config.json").write_text(json.dumps(output, sort_keys=True, indent=2) + "\n")
            bundles[name] = bundle
        details = []
        for name, raw, _ in cases[:3]:
            result = command(protected_runtime, state, "run", "--no-pivot", "--bundle",
                             str(bundles[name]), name)
            log = (result.stdout + result.stderr).decode(errors="replace")
            (run_dir / f"{name}.log").write_text(log)
            if result.returncode != 0:
                raise AssertionError(f"{name} runc exit {result.returncode}: {log[-500:]}")
            rows = cap_probe_rows(log, 0x2000 if raw else 0, ("INIT", "CHILD_EXEC"))
            details.append({"case": name, "exit": result.returncode, "probe_rows": rows,
                            "log_sha256": sha256(run_dir / f"{name}.log")})
        with (run_dir / "held-start.log").open("wb") as stream:
            held = subprocess.run([str(protected_runtime), "--root", str(state), "run",
                                   "--no-pivot", "--detach", "--bundle",
                                   str(bundles["held"]), "held"],
                                  stdin=subprocess.DEVNULL, stdout=stream,
                                  stderr=subprocess.STDOUT, timeout=15, check=False)
        if held.returncode != 0:
            raise AssertionError(f"held container failed: {(run_dir / 'held-start.log').read_text(errors='replace')[-500:]}")
        protected_record = private_root / "approved/held/config.json"
        protected_record.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        protected_record.parent.parent.chmod(0o700)
        protected_record.parent.chmod(0o700)
        protected_record.write_bytes((bundles["held"] / "config.json").read_bytes())
        protected_record.chmod(0o600)
        if sha256(protected_record) != sha256(bundles["held"] / "config.json"):
            raise AssertionError("protected creation record differs from the launched bundle")
        receipt["protected_record_sha256"] = sha256(protected_record)
        policy_path = run_dir / "exec-policy.json"
        policy_path.write_text('{"allowed_capabilities":["CAP_NET_RAW"]}\n')
        safe = spec(False, ["/bin/live-probe", "deny", "exec"])["process"]
        # Omitted groups must be emitted explicitly by the production entry.
        safe["capabilities"] = {}
        checked_safe = check_exec(safe, ["CAP_NET_RAW"], [])
        if any(checked_safe["capabilities"].values()) or len(checked_safe["capabilities"]) != 5:
            raise AssertionError("omitted exec groups were not normalized to five empty sets")
        safe_path = run_dir / "exec-safe.json"
        safe_path.write_text(json.dumps(safe, sort_keys=True, indent=2) + "\n")
        gate_command = [sys.executable, str(PROJECT / "src/container_capability_gate.py"),
                        "run-exec", "--policy", str(policy_path),
                        "--created-spec", str(protected_record), "--runtime", str(protected_runtime),
                        "--runtime-root", str(state), "--id", "held",
                        "--private-root", str(private_root)]
        safe_result = subprocess.run([*gate_command, "--input", str(safe_path)],
                                     input=b"", capture_output=True, timeout=15, check=False)
        safe_log = (safe_result.stdout + safe_result.stderr).decode(errors="replace")
        (run_dir / "exec-safe.log").write_text(safe_log)
        if safe_result.returncode != 0:
            raise AssertionError(f"checked OCI exec failed: {safe_log[-500:]}")
        details.append({"case": "exec-safe-via-run-exec", "exit": safe_result.returncode,
                        "probe_rows": cap_probe_rows(safe_log, 0,
                                                     ("OCI_EXEC", "OCI_EXEC_CHILD")),
                        "log_sha256": sha256(run_dir / "exec-safe.log")})
        unsafe = spec(True, ["/bin/live-probe", "allow", "exec"])["process"]
        unsafe_path = run_dir / "exec-unsafe-direct.json"
        unsafe_path.write_text(json.dumps(unsafe, sort_keys=True, indent=2) + "\n")
        rejected = subprocess.run([*gate_command, "--input", str(unsafe_path)],
                                  input=b"", capture_output=True, timeout=15, check=False)
        receipt["unsafe_run_exec_exit"] = rejected.returncode
        receipt["unsafe_run_exec_output"] = (rejected.stdout + rejected.stderr).decode(errors="replace")
        if rejected.returncode != 2 or "exceeds approved creation capabilities" not in \
                receipt["unsafe_run_exec_output"]:
            raise AssertionError("run-exec did not reject capability omitted at creation")
        # Direct runtime path is an intentional ungated control, not an upstream bug.
        unsafe_result = command(protected_runtime, state, "exec", "--process", str(unsafe_path), "held")
        unsafe_log = (unsafe_result.stdout + unsafe_result.stderr).decode(errors="replace")
        (run_dir / "exec-unsafe-direct.log").write_text(unsafe_log)
        if unsafe_result.returncode != 0:
            raise AssertionError(f"ungated direct OCI exec control failed: {unsafe_log[-500:]}")
        details.append({"case": "exec-unsafe-direct", "exit": unsafe_result.returncode,
                        "probe_rows": cap_probe_rows(unsafe_log, 0x2000,
                                                     ("OCI_EXEC", "OCI_EXEC_CHILD")),
                        "log_sha256": sha256(run_dir / "exec-unsafe-direct.log")})
        receipt["checks"] = details
        receipt["status"] = "PASS"
    except AssertionError as error:
        receipt.update(status="FAIL", error=str(error))
    except Exception as error:
        receipt.update(status="OPEN", error=f"{type(error).__name__}: {error}")
    finally:
        if "state" in locals() and "protected_runtime" in locals():
            # A cleanup issue leaves the isolated test lifecycle unverified.
            try:
                result = command(protected_runtime, state, "kill", "held", "SIGKILL", timeout=5)
                receipt["held_kill_exit"] = result.returncode
                result = command(protected_runtime, state, "delete", "--force", "held", timeout=5)
                receipt["held_delete_exit"] = result.returncode
            except Exception as error:
                receipt["cleanup_error"] = f"{type(error).__name__}: {error}"
            if receipt["status"] == "PASS" and (receipt.get("held_kill_exit") != 0 or
                                                receipt.get("held_delete_exit") != 0 or
                                                "cleanup_error" in receipt):
                receipt.update(status="OPEN", error="owned test container cleanup did not complete")
    receipt_path = run_dir / "receipt.json"
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    print(f"{receipt['status']} {receipt_path}")
    if receipt["status"] != "PASS":
        print(receipt.get("error", "unknown error"), file=sys.stderr)
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
