"""OrionVM VPN 接管核心 —— OpenVPN 进程编排 + 出口 IP 验证 + 候选切换.

模块边界:
    takeover.OVPNManager   进程级控制: 启动 / 停止 / 检测当前出口 IP / 切换节点
    takeover.inject_modes  把 .ovpn 文本改造成 'out' (只接管出站) 或 'full' (双向)
"""
from __future__ import annotations

import logging
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .models import Node
from .utils import Logger

Mode = Literal["out", "full"]


# ------------------- config 注入 -------------------

# 移除服务端 push 的 redirect-gateway 自己接管
_REDIRECT_LINE_RE = re.compile(r"^\s*(?:push\s+[\"']?)?redirect-gateway[^\n]*", re.IGNORECASE | re.MULTILINE)
_BLOCK_OUTSIDE_DNS_RE = re.compile(r"^\s*block-outside-dns[^\n]*", re.IGNORECASE | re.MULTILINE)
_DHCP_OPTION_RE = re.compile(r"^\s*dhcp-option\s+DNS[^\n]*", re.IGNORECASE | re.MULTILINE)


def inject_outbound_mode(config: str, mode: Mode) -> str:
    """替换/注入 redirect-gateway 指令.

    - "out"  → redirect-gateway local def1   (Linux/macOS 只接管出栈)
    - "full" → redirect-gateway def1 bypass-dhcp   (双向接管)

    同时剥离服务端 push 的 redirect-gateway 行和 block-outside-dns, 避免冲突.
    """
    if not config:
        return config

    cleaned = _REDIRECT_LINE_RE.sub("", config)
    cleaned = _BLOCK_OUTSIDE_DNS_RE.sub("", cleaned)
    cleaned = _DHCP_OPTION_RE.sub("", cleaned)

    # 选定要插入的指令行
    if mode == "out":
        inject_lines = (
            "# -- injected by orionvm (mode=out) --",
            "redirect-gateway local def1",
        )
    else:
        inject_lines = (
            "# -- injected by orionvm (mode=full) --",
            "redirect-gateway def1 bypass-dhcp",
            "block-outside-dns",
        )

    # 在第一个 remote 行之前插入, 避免被 remote-cert-tls 等覆盖
    lines = cleaned.splitlines()
    insert_at = 0
    for i, line in enumerate(lines):
        ls = line.strip().lower()
        if ls.startswith("remote ") or ls.startswith("up ") or ls.startswith("down "):
            insert_at = i
            break
        insert_at = i + 1

    return "\n".join(lines[:insert_at] + list(inject_lines) + lines[insert_at:]) + "\n"


# ------------------- OVPN 进程 -------------------

@dataclass(slots=True)
class OVPNResult:
    started: bool
    exit_ip: str | None
    msg: str


class OVPNManager:
    """启停一个 openvpn daemon, 验证连接后的公网 IP."""

    def __init__(
        self,
        *,
        ovpn_path: Path,
        ovpn_log: Path,
        connect_timeout: int = 25,
        log: Logger | None = None,
    ) -> None:
        self.ovpn_path = ovpn_path
        self.ovpn_log = ovpn_log
        self.connect_timeout = connect_timeout
        self.log = log or Logger()

    # ---- 子进程 ----

    def _stop(self) -> None:
        if shutil.which("pkill"):
            subprocess.run(["pkill", "openvpn"], capture_output=True, check=False)
            time.sleep(1)

    @staticmethod
    def _running() -> bool:
        if not shutil.which("pgrep"):
            return False
        r = subprocess.run(["pgrep", "-x", "openvpn"], capture_output=True, text=True)
        return r.returncode == 0

    @staticmethod
    def _check_log_completed(path: Path) -> bool:
        try:
            if not path.exists():
                return False
            text = path.read_text(errors="replace")
        except OSError:
            return False
        return "Initialization Sequence Completed" in text

    # ---- 入口 ----

    def start(self, config_text: str, mode: Mode) -> OVPNResult:
        self._stop()
        try:
            self.ovpn_path.parent.mkdir(parents=True, exist_ok=True)
            self.ovpn_path.write_text(inject_outbound_mode(config_text, mode), encoding="utf-8")
        except OSError as e:
            return OVPNResult(False, None, f"write config failed: {e}")
        # 清理旧日志
        try:
            self.ovpn_log.unlink(missing_ok=True)
        except OSError:
            pass

        if not shutil.which("openvpn"):
            return OVPNResult(False, None, "openvpn binary not found in PATH")

        cmd = [
            "openvpn",
            "--config", str(self.ovpn_path),
            "--daemon",
            "--log", str(self.ovpn_log),
            "--verb", "3",
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as e:
            return OVPNResult(False, None, f"openvpn spawn failed: {e}")

        # 等握手
        deadline = time.time() + self.connect_timeout
        while time.time() < deadline:
            if self._check_log_completed(self.ovpn_log):
                break
            time.sleep(1)
        else:
            self._stop()
            tail = self._read_log_tail(800)
            return OVPNResult(False, None, f"connect timeout. log tail:\n{tail}")

        exit_ip = self._probe_public_ip()
        if exit_ip is None:
            self._stop()
            return OVPNResult(False, None, "connected, but cannot reach public IP probe (DNS or routing broken?)")
        return OVPNResult(True, exit_ip, "ok")

    def stop(self) -> None:
        self._stop()

    def is_running(self) -> bool:
        return self._running() or self._check_log_completed(self.ovpn_log)

    # ---- helpers ----

    def _read_log_tail(self, n: int) -> str:
        try:
            data = self.ovpn_log.read_text(errors="replace")
        except OSError:
            return ""
        return data[-n:]

    def _probe_public_ip(self, urls: tuple[str, ...] | None = None) -> str | None:
        urls = urls or (
            "https://api.ipify.org",
            "https://api64.ipify.org",
            "https://icanhazip.com",
            "https://checkip.amazonaws.com",
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "orionvm/0.2"})
                with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                    body = resp.read().decode("utf-8", errors="replace").strip()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", body):
                        return body
            except Exception:
                continue
        return None


# ------------------- 节点切换 -------------------

def tcp_alive(host: str, port: int, timeout: float = 5.0) -> bool:
    """TCP 端口可达性 (用于切换前的存活性预筛)."""
    try:
        af = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(af, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except OSError:
        return False


__all__ = [
    "OVPNManager",
    "OVPNResult",
    "Mode",
    "inject_outbound_mode",
    "tcp_alive",
]
