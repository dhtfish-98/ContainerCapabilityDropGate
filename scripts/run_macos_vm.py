"""Run the capability gate and its actual OCI container controls in a Linux VM."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import time


PROJECT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(PROJECT))
from src.container_capability_gate import PolicyError, check_exec, prepare  # noqa: E402


PINS = {
    "Image-6.18.52-0-virt": "8dfe2ce7e5bfe4d0efcf2fed0a01a692b5a5d5217e9a55587a17d92203ab7b0d",
    "initramfs-virt": "b0be51c9de43d582da897df3583114192933872a7e219218752b18082d75b6cb",
    "config-6.18.52-0-virt": "18bb325df712efc698503ab3442f4c41017d9799a728464b7ec8a5b86ea9cf10",
    "zig": "90b31f6630e0489bc4f6fd41b70dcfde8fce434636cff15a61d57061b10a4abb",
    "runc.arm64": "d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_static_arm64(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise RuntimeError(f"{path.name} is not an AArch64 ELF")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    entsize, count = struct.unpack_from("<HH", data, 54)
    if entsize < 56 or phoff + entsize * count > len(data):
        raise RuntimeError(f"{path.name} ELF program headers are invalid")
    if any(struct.unpack_from("<I", data, phoff + i * entsize)[0] == 3 for i in range(count)):
        raise RuntimeError(f"{path.name} depends on a dynamic interpreter")
    return {"architecture": "AArch64", "static": True, "sha256": sha256(path)}


def spec(raw: bool, expectation: str) -> dict:
    caps = ["CAP_NET_RAW"] if raw else []
    return {
        "ociVersion": "1.3.0",
        "process": {"terminal": False, "user": {"uid": 0, "gid": 0},
                    "args": ["/bin/live-probe", expectation], "env": ["PATH=/bin"],
                    "cwd": "/", "noNewPrivileges": True,
                    "capabilities": {"bounding": caps, "effective": caps, "permitted": caps,
                                     "inheritable": [], "ambient": []}},
        "root": {"path": "rootfs", "readonly": False},
        "hostname": "capability-lab",
        "mounts": [{"destination": "/proc", "type": "proc", "source": "proc"},
                   {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
                    "options": ["nosuid", "mode=755"]}],
        "linux": {"namespaces": [{"type": name} for name in
                                ("pid", "mount", "network", "ipc", "uts")]},
    }


def create_overlay(run_dir: Path, probe: Path, runc: Path) -> tuple[Path, dict]:
    overlay = run_dir / "overlay"
    (overlay / "usr/bin").mkdir(parents=True)
    shutil.copy2(runc, overlay / "usr/bin/runc")
    shutil.copy2(PROJECT / "tests/guest_test.sh", overlay / "usr/bin/guest_test.sh")
    (overlay / "usr/bin/runc").chmod(0o755)
    policies = {"guard": [], "allow": ["CAP_NET_RAW"]}
    for name in ("baseline", "guard", "allow", "held"):
        bundle = overlay / "opt/ccdg" / name
        for relative in ("rootfs/bin", "rootfs/proc", "rootfs/dev"):
            (bundle / relative).mkdir(parents=True, exist_ok=True)
        shutil.copy2(probe, bundle / "rootfs/bin/live-probe")
        (bundle / "rootfs/bin/live-probe").chmod(0o755)
        if name == "baseline":
            # Synthetic owned weak configuration: not an upstream defect.
            output = spec(True, "allow")
        else:
            selected = policies.get(name, [])
            template = spec(bool(selected), "allow" if name == "allow" else "deny")
            if name == "held":
                template["process"]["args"] = ["/bin/live-probe", "hold"]
            output = prepare(template, selected)
        (bundle / "config.json").write_text(json.dumps(output, sort_keys=True, indent=2) + "\n")

    safe_exec = spec(False, "deny")["process"]
    safe_exec["args"] = ["/bin/live-probe", "deny", "exec"]
    check_exec(safe_exec, [], [])
    (overlay / "opt/ccdg/exec-safe.json").write_text(
        json.dumps(safe_exec, sort_keys=True, indent=2) + "\n")

    unsafe_exec = spec(True, "allow")["process"]
    unsafe_exec["args"] = ["/bin/live-probe", "allow", "exec"]
    (overlay / "opt/ccdg/exec-unsafe-direct.json").write_text(
        json.dumps(unsafe_exec, sort_keys=True, indent=2) + "\n")

    try:
        prepare(spec(True, "allow"), [])
    except PolicyError:
        outside_policy_rejected = True
    else:
        outside_policy_rejected = False
    try:
        check_exec(unsafe_exec, [], [])
    except PolicyError:
        exec_cap_regain_rejected = True
    else:
        exec_cap_regain_rejected = False
    if not outside_policy_rejected or not exec_cap_regain_rejected:
        raise AssertionError("policy accepted a capability outside the allowlist")
    return overlay, {"outside_policy_rejected": outside_policy_rejected,
                     "exec_cap_regain_rejected": exec_cap_regain_rejected}


def make_initramfs(overlay: Path, base: Path, output: Path) -> None:
    entries = ".\n" + "\n".join(str(p.relative_to(overlay)) for p in sorted(overlay.rglob("*"))) + "\n"
    archive = subprocess.run(["cpio", "-o", "-H", "newc"], cwd=overlay,
                             input=entries.encode(), capture_output=True, check=True).stdout
    output.write_bytes(gzip.compress(gzip.decompress(base.read_bytes()) + archive,
                                     compresslevel=9, mtime=0))


def boot_and_capture(host: Path, kernel: Path, initramfs: Path, log: Path) -> tuple[int, str]:
    master, slave = pty.openpty()
    process = subprocess.Popen([str(host), str(kernel), str(initramfs)],
                               stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    captured = bytearray()
    sent = False
    deadline = time.monotonic() + 90
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    data = os.read(master, 32768)
                except OSError:
                    break
                if not data:
                    break
                captured.extend(data)
                if not sent and b"~ #" in captured:
                    os.write(master, b"/bin/sh /usr/bin/guest_test.sh\n")
                    sent = True
            if process.poll() is not None and not ready:
                break
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    finally:
        os.close(master)
        log.write_bytes(captured)
    if not sent:
        raise RuntimeError("Linux guest shell never became available")
    return process.returncode, captured.decode(errors="replace").replace("\r", "")


def verify(serial: str, vm_exit: int) -> dict:
    if vm_exit != 0 or "KERNEL_RELEASE=6.18.52-0-virt" not in serial or \
            "runc version 1.5.2" not in serial or "TEST_EXIT=0" not in serial:
        raise AssertionError("VM, kernel, runtime or test script did not complete")
    for name in ("BASELINE", "GUARD", "ALLOW", "HELD_START", "EXEC_SAFE", "UNSAFE_DIRECT_EXEC"):
        if f"{name}_EXIT=0" not in serial:
            raise AssertionError(f"{name} container failed")
    pattern = (r"^PHASE=(INIT|CHILD_EXEC|OCI_EXEC|OCI_EXEC_CHILD) CapEff=([0-9a-f]{16}) CapPrm=([0-9a-f]{16}) "
               r"CapBnd=([0-9a-f]{16}) CapInh=([0-9a-f]{16}) CapAmb=([0-9a-f]{16}) "
               r"RAW_SOCKET=(ALLOW|DENY) errno=(\d+)$")
    lines = re.findall(pattern, serial, re.M)
    if len(lines) != 10 or serial.count("PROBE_RESULT=PASS") != 5:
        raise AssertionError("expected three init and two OCI exec probes with children")
    observed = []
    for index, row in enumerate(lines):
        case = ("baseline", "guard", "allow", "exec-safe", "exec-unsafe-direct")[index // 2]
        phase, eff, prm, bnd, inh, amb, operation, error = row
        expected = 0x2000 if case in ("baseline", "allow", "exec-unsafe-direct") else 0
        expected_phase = (("OCI_EXEC", "OCI_EXEC_CHILD") if case.startswith("exec-")
                          else ("INIT", "CHILD_EXEC"))[index % 2]
        if phase != expected_phase or \
                any(int(value, 16) != expected for value in (eff, prm, bnd)) or \
                int(inh, 16) != 0 or int(amb, 16) != 0 or \
                operation != ("ALLOW" if expected else "DENY") or \
                int(error) != (0 if expected else 1):
            raise AssertionError(f"capability or kernel operation mismatch in {case}/{phase}")
        observed.append({"case": case, "phase": phase, "cap_eff": eff,
                         "cap_prm": prm, "cap_bnd": bnd, "cap_inh": inh,
                         "cap_amb": amb, "raw_socket": operation, "errno": int(error)})
    return {"container_probes": observed, "runtime": "runc v1.5.2",
            "kernel": "6.18.52-0-virt",
            "direct_exec_case": "intentional ungated owned weak configuration; not an upstream vulnerability"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--run-id")
    args = parser.parse_args()
    build = args.build_root.resolve()
    if build.name != "Build":
        parser.error("--build-root must be the workspace Build directory")
    run_id = args.run_id or datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", run_id):
        parser.error("invalid run ID")
    run_dir = build / "验证/ContainerCapabilityDropGate-20261006" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    receipt = {"status": "OPEN", "created_utc": datetime.now(timezone.utc).isoformat(),
               "run_id": run_id, "source_root": str(PROJECT), "run_dir": str(run_dir),
               "host_platform": platform.platform()}
    serial_path = run_dir / "vm-serial.log"
    try:
        if sys.platform != "darwin" or platform.machine() != "arm64":
            raise RuntimeError("Apple silicon macOS Virtualization.framework is required")
        env = build / "环境/LandlockFilesystemGate-20261006"
        runtime = build / "环境/ContainerCapabilityDropGate-20261006/runc.arm64"
        kernel = env / "Image-6.18.52-0-virt"
        base = env / "initramfs-virt"
        config = env / "config-6.18.52-0-virt"
        zig = env / "zig-macos-aarch64-0.13.0/zig"
        for path, key in ((kernel, kernel.name), (base, base.name), (config, config.name),
                          (zig, "zig"), (runtime, runtime.name)):
            if not path.is_file() or sha256(path) != PINS[key]:
                raise RuntimeError(f"missing or changed pinned environment component: {key}")
        receipt["environment_sha256"] = dict(PINS)
        required = ("CONFIG_CGROUPS=y", "CONFIG_NAMESPACES=y", "CONFIG_PID_NS=y",
                    "CONFIG_NET_NS=y", "CONFIG_SECCOMP=y")
        if any(marker not in config.read_text() for marker in required):
            raise RuntimeError("pinned kernel lacks a required isolation feature")
        probe = run_dir / "live-probe"
        compile_env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(run_dir / "zig-global-cache"),
                           ZIG_LOCAL_CACHE_DIR=str(run_dir / "zig-local-cache"))
        with (run_dir / "probe.compile.log").open("w") as stream:
            subprocess.run([str(zig), "cc", "-target", "aarch64-linux-musl", "-static", "-O2",
                            "-Wall", "-Wextra", "-Werror", str(PROJECT / "tests/live_probe.c"),
                            "-o", str(probe)], check=True, env=compile_env,
                           stdout=stream, stderr=subprocess.STDOUT)
        receipt["probe_binary"] = require_static_arm64(probe)
        receipt["runtime_binary"] = require_static_arm64(runtime)
        receipt["source_sha256"] = {str(path.relative_to(PROJECT)): sha256(path) for path in (
            PROJECT / "src/container_capability_gate.py", PROJECT / "tests/live_probe.c",
            PROJECT / "tests/guest_vm.swift", PROJECT / "tests/guest_test.sh",
            PROJECT / "tests/test_policy.py", PROJECT / "tests/virtualization.entitlements",
            Path(__file__))}
        overlay, policy_checks = create_overlay(run_dir, probe, runtime)
        receipt["policy_checks"] = policy_checks
        initramfs = run_dir / "initramfs-with-containers.gz"
        make_initramfs(overlay, base, initramfs)
        receipt["guest_initramfs_sha256"] = sha256(initramfs)
        host = run_dir / "guest_vm"
        with (run_dir / "swift.compile.log").open("w") as stream:
            subprocess.run(["swiftc", "-parse-as-library", "-framework", "Virtualization",
                            str(PROJECT / "tests/guest_vm.swift"), "-o", str(host)],
                           check=True, stdout=stream, stderr=subprocess.STDOUT)
        subprocess.run(["codesign", "--force", "--sign", "-", "--entitlements",
                        str(PROJECT / "tests/virtualization.entitlements"), str(host)],
                       check=True, capture_output=True)
        vm_exit, serial = boot_and_capture(host, kernel, initramfs, serial_path)
        receipt["vm_exit"] = vm_exit
        receipt["serial_sha256"] = sha256(serial_path)
        receipt["checks"] = verify(serial, vm_exit)
        receipt["status"] = "PASS"
    except AssertionError as error:
        receipt.update(status="FAIL", error=str(error))
    except Exception as error:
        receipt.update(status="OPEN", error=f"{type(error).__name__}: {error}")
    if serial_path.exists() and "serial_sha256" not in receipt:
        receipt["serial_sha256"] = sha256(serial_path)
    receipt_path = run_dir / "receipt.json"
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    print(f"{receipt['status']} {receipt_path}")
    if receipt["status"] != "PASS":
        print(receipt.get("error", "unknown error"), file=sys.stderr)
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
