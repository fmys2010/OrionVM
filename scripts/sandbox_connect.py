"""OrionVM 远端沙箱测试 —— SSH 到 arc.fmys.dev:28905，启动 Docker 容器做集成验证。

依赖:
    - OpenSSH ssh (内置 SSH_ASKPASS 支持)
    - 密码文件: 脚本同目录下的 pw.yaml 或 pw.json
        pw.yaml:   pw: "your-root-password"
        pw.json:   { "pw": "your-root-password" }
      或环境变量 ORIONVM_PW（优先级最低）。
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

HOST = "arc.fmys.dev"
PORT = "28905"
USER = "root"

PW_ENV = "ORIONVM_PW"
ASKPASS_SCRIPT = "/tmp/orionvm-askpass.sh"


def _read_yaml_simple(path: Path) -> dict:
    """Minimal single-key YAML parser: only handles top-level 'key: value'."""
    data: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FileNotFoundError(str(exc)) from exc
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip()
        if not k:
            continue
        v = v.strip().strip("\"'")
        if v:
            data[k] = v
    return data


def load_pw() -> str:
    """优先走 ORIONVM_PW 环境变量, 其次 pw.yaml / pw.json (同脚本目录)."""
    pw = os.environ.get(PW_ENV)
    if pw:
        return pw
    here = Path(__file__).resolve().parent
    for rel in ("pw.yaml", "pw.yml", "pw.json"):
        pw_file = here / rel
        if not pw_file.exists():
            pw_file = here.parent / rel
        if not pw_file.exists():
            continue
        if pw_file.suffix.lower() in (".yaml", ".yml"):
            data = _read_yaml_simple(pw_file)
            val = str(data.get("pw", "")).strip()
            if val:
                return val
            continue
        try:
            raw = json.loads(pw_file.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                val = str(raw.get("pw", "")).strip()
                if val:
                    return val
        except (json.JSONDecodeError, OSError):
            continue
    raise FileNotFoundError(
        "Password not found. Please set env ORIONVM_PW "
        f"or place pw.yaml/pw.json at {here}"
    )


def run_ssh(cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a single SSH command non-interactively via SSH_ASKPASS."""
    pw = load_pw()
    env = os.environ.copy()
    env["DISPLAY"] = "dummy"
    env["SSH_ASKPASS"] = ASKPASS_SCRIPT
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env[PW_ENV] = pw
    full = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=no",
        "-o", "PubkeyAuthentication=no",
        "-p", PORT,
        f"{USER}@{HOST}",
        cmd,
    ]
    return subprocess.run(
        full,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_scp(local: str, remote: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """Push a file via scp (also password-based, same mechanism)."""
    pw = load_pw()
    env = os.environ.copy()
    env["DISPLAY"] = "dummy"
    env["SSH_ASKPASS"] = ASKPASS_SCRIPT
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env[PW_ENV] = pw
    # copy special-case the script itself for mention, remote -> file
    full = [
        "scp",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=no",
        "-o", "PubkeyAuthentication=no",
        "-P", PORT,
        local,
        f"{USER}@{HOST}:{remote}",
    ]
    return subprocess.run(
        full,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def phase1_smoke() -> bool:
    """Phase 1: just check we can SSH in."""
    print("[phase1] SSH smoke test ...")
    r = run_ssh("uname -a && cat /etc/os-release | head -4 && docker --version && whoami")
    print(r.stdout.strip())
    if r.returncode != 0:
        print("[phase1] stderr:", r.stderr.strip()[:500])
        return False
    return True


def phase2_setup_container(project_dir: str = "/root/OrionVM") -> bool:
    """Phase 2: stop any previous box, drop a fresh one."""
    print("[phase2] spinning up Docker sandbox container ...")
    cmds = [
        f"docker rm -f orionvm-sandbox 2>/dev/null; "
        f"docker run -d --name orionvm-sandbox --privileged "
        f"--cap-add=NET_ADMIN --device=/dev/net/tun "
        f"-v {project_dir}:/workspace "
        f"ubuntu:24.04 sleep infinity",
        "sleep 3",
        "docker exec orionvm-sandbox apt-get update -qq "
        "&& docker exec orionvm-sandbox apt-get install -y -qq "
        "python3 python3-pip openvpn iputils-ping kmod 2>&1 | tail -5",
        "docker exec orionvm-sandbox mkdir -p /dev/net && "
        "docker exec orionvm-sandbox mknod /dev/net/tun c 10 200 2>/dev/null || true",
        "docker exec orionvm-sandbox ls /workspace | head -5",
    ]
    for c in cmds:
        r = run_ssh(c, timeout=120)
        print(r.stdout.strip())
        if r.returncode != 0:
            print("[phase2] failed cmd:", c[:120])
            print("stderr:", r.stderr.strip()[:500])
            return False
    return True


def phase3_run_orionvm_scan() -> bool:
    """Phase 3: run orionvm scan inside the container for real."""
    print("[phase3] running orionvm scan inside container ...")
    c = (
        "docker exec orionvm-sandbox bash -lc "
        "'cd /workspace && python3 -m orionvm scan --max-scan 20 --workers 8 --top 5 2>&1 | tail -40'"
    )
    r = run_ssh(c, timeout=300)
    print(r.stdout.strip())
    if r.returncode != 0:
        print("[phase3] stderr:", r.stderr.strip()[:800])
        return False
    return True


def main() -> int:
    if not Path(ASKPASS_SCRIPT).exists():
        print(f"Missing {ASKPASS_SCRIPT}, create it with a shebang + echo \"${{ORIONVM_PW}}\"")
        return 2

    ok = phase1_smoke()
    if not ok:
        print("SSH smoke failed, aborting.")
        return 1
    ok = phase2_setup_container()
    if not ok:
        print("Container setup failed, aborting.")
        return 1
    ok = phase3_run_orionvm_scan()
    if not ok:
        print("orionvm scan inside sandbox failed.")
        return 1
    print("All phases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
