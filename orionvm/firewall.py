"""OrionVM Linux 防火墙调度 —— 仅 Linux (iptables + ip6tables).

设计目标:
    "只接管出站": 通过 OpenVPN `redirect-gateway local` 改路由 + iptables
    拦截物理网卡主动出栈 (VPN 端口 + DNS 例外). 任一时刻 OUTPUT 默认 DROP,
    除 tun0 / VPN 握手 / DNS 之外的包统统拒掉.

调用模式:
    firewall.apply_lock(endpoint, mode="out")  -> 装锁
    firewall.revert()                          -> 卸锁, 恢复默认 ACCEPT
    firewall.status()                          -> 打印当前规则概要

注意: 仅 Linux, 但模块导入在 Windows 上不报错 (只调用时报错).
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class VpnEndpoint:
    server_ip: str
    port: int = 1194
    proto: str = "udp"      # udp / tcp
    iface_phys: str = "eth0"
    iface_vpn: str = "tun0"


# 标记用 chain 名, 便于查询/清理
ORIONVM_TAG = "ORIONVM-MANAGED"


class FirewallError(RuntimeError):
    pass


# ---------- 平台门 ----------

def _require_root_or_sudo() -> None:
    if platform.system() != "Linux":
        raise FirewallError(f"only Linux supported (got {platform.system()})")
    if os.geteuid() == 0:
        return
    if not shutil.which("sudo"):
        raise FirewallError("neither root nor sudo available; cannot modify iptables")


def _run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    """以 root (或 sudo) 跑一段命令."""
    if os.geteuid() != 0 and shutil.which("sudo"):
        args = ["sudo", *args]
    return subprocess.run(args, capture_output=True, text=True, check=check)


def _iptables_present() -> bool:
    return shutil.which("iptables") is not None


def _ip6tables_present() -> bool:
    return shutil.which("ip6tables") is not None


# ---------- 应用 ----------

def apply_lock(endpoint: VpnEndpoint) -> None:
    """装锁: 仅出栈, kill-switch, 防 IPv6 leak.

    规则总览 (IPv4):
        -P OUTPUT DROP
        -A OUTPUT -o lo               -j ACCEPT
        -A OUTPUT -o <vpn>            -j ACCEPT
        -A OUTPUT -o <phy> -p udp --dport 53  -j ACCEPT   # DNS
        -A OUTPUT -o <phy> -p tcp --dport 53  -j ACCEPT   # DNS over TCP
        -A OUTPUT -d <VPN_IP> -p <proto> --dport <port> -o <phy> -j ACCEPT
        -A OUTPUT -o <phy> -m state --state ESTABLISHED,RELATED -j ACCEPT

    IPv6: 出栈全 DROP (防 leak), 入栈不动 (保留 SSHv6 等本地服务).
    """
    _require_root_or_sudo()
    if not _iptables_present():
        raise FirewallError("iptables not found in PATH")

    cmd_v4: list[list[str]] = [
        ["iptables", "-F", "OUTPUT"],
        ["iptables", "-P", "OUTPUT", "DROP"],
        # 打标记, revert 时认这个 comment 找
        ["iptables", "-A", "OUTPUT", "-m", "comment", "--comment", ORIONVM_TAG,
         "-o", "lo", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-m", "comment", "--comment", ORIONVM_TAG,
         "-o", endpoint.iface_vpn, "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-m", "comment", "--comment", ORIONVM_TAG,
         "-o", endpoint.iface_phys, "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-m", "comment", "--comment", ORIONVM_TAG,
         "-o", endpoint.iface_phys, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-m", "comment", "--comment", ORIONVM_TAG,
         "-d", endpoint.server_ip, "-p", endpoint.proto,
         "--dport", str(endpoint.port), "-o", endpoint.iface_phys,
         "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-m", "comment", "--comment", ORIONVM_TAG,
         "-o", endpoint.iface_phys, "-m", "state",
         "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ]
    for c in cmd_v4:
        _run(c, check=False)

    # IPv6: 防 leak (出栈全 DROP)
    if _ip6tables_present():
        cmd_v6: list[list[str]] = [
            ["ip6tables", "-F", "OUTPUT"],
            ["ip6tables", "-P", "OUTPUT", "DROP"],
            ["ip6tables", "-A", "OUTPUT", "-m", "comment", "--comment", ORIONVM_TAG,
             "-o", "lo", "-j", "ACCEPT"],
            ["ip6tables", "-A", "OUTPUT", "-m", "comment", "--comment", ORIONVM_TAG,
             "-o", endpoint.iface_vpn, "-j", "ACCEPT"],
            ["ip6tables", "-A", "OUTPUT", "-m", "comment", "--comment", ORIONVM_TAG,
             "-o", endpoint.iface_phys, "-j", "DROP"],
        ]
        for c in cmd_v6:
            _run(c, check=False)


def revert() -> None:
    """卸锁: 删除 orionvm 标记的所有规则, 恢复 OUTPUT 默认 ACCEPT."""
    if platform.system() != "Linux":
        return
    if os.geteuid() != 0 and not shutil.which("sudo"):
        return

    for tbl in ("iptables", "ip6tables"):
        if not shutil.which(tbl):
            continue
        # 列出数字编号, 然后反向选择带 comment 的删除 (不能用 -F 因为可能误删用户现有规则)
        r = subprocess.run(
            ["sudo", tbl, "-S", "OUTPUT", "--line-numbers", "-n"] if os.geteuid() != 0
            else [tbl, "-S", "OUTPUT", "--line-numbers", "-n"],
            capture_output=True, text=True, check=False,
        )
        for line in r.stdout.splitlines():
            if ORIONVM_TAG not in line:
                continue
            num = line.split()[0].rstrip(":")
            subprocess.run(
                (["sudo"] if os.geteuid() != 0 else [])
                + [tbl, "-D", "OUTPUT", num],
                capture_output=True, check=False,
            )
        # 最后恢复默认 ACCEPT
        _run([tbl, "-P", "OUTPUT", "ACCEPT"], check=False)


def status() -> str:
    """返回当前 OUTPUT 链规则概要 (诊断用)."""
    if platform.system() != "Linux":
        return f"<non-linux platform: {platform.system()}>"
    parts: list[str] = []
    for tbl in ("iptables", "ip6tables"):
        if not shutil.which(tbl):
            continue
        r = _run([tbl, "-L", "OUTPUT", "-n", "-v", "--line-numbers"], check=False)
        parts.append(f"=== {tbl} OUTPUT ===\n{r.stdout.strip()}")
    # 默认策略
    pol4 = _run(["iptables", "-S", "OUTPUT"], check=False).stdout.strip()
    return ("\n\n".join(parts) if parts else "no rules available") + f"\n\npolicy: {pol4}"


def active() -> bool:
    """快速探测: iptables OUTPUT 是否包含 orionvm 标记."""
    if platform.system() != "Linux":
        return False
    r = _run(["iptables", "-S", "OUTPUT"], check=False)
    return ORIONVM_TAG in (r.stdout or "")


__all__ = ["VpnEndpoint", "FirewallError", "apply_lock", "revert", "status", "active"]
