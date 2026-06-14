"""OrionVM 运行时配置 —— 优先环境变量, 兼顾 CLI / 配置文件."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .utils import safe_int

Mode = Literal["full", "out"]


@dataclass(slots=True)
class RuntimeConfig:
    # ---- 路径 ----
    base_dir: Path = field(default_factory=lambda: Path.cwd())
    data_dir: Path = field(default_factory=lambda: Path("data"))
    pid_file: Path = field(default_factory=lambda: Path("data/daemon.pid"))
    log_file: Path = field(default_factory=lambda: Path("data/daemon.log"))

    # ---- 过滤与刷新 ----
    max_scan: int = 80
    top_n: int = 20
    workers: int = 16
    refresh_interval: int = 5 * 3600       # 后台异步刷新间隔
    run_geo: bool = True                   # 是否做 IP 质量查询 (--no-geo 关掉)

    # ---- 接管 ----
    underway_mode: Mode = "out"            # "out" = 只接管出站
    ovpn_path: Path = Path("/tmp/orionvm.ovpn")
    ovpn_log: Path = Path("/tmp/orionvm_ovpn.log")
    connect_timeout: int = 25

    # ---- 防火墙 ----
    iface_phys: str = "eth0"
    iface_vpn: str = "tun0"
    auto_firewall: bool = True             # 是否在 start/stop 自动套/撤 iptables 规则

    # ---- 公网探测 ----
    probe_urls: tuple[str, ...] = (
        "https://api.ipify.org",
        "https://api64.ipify.org",
        "https://icanhazip.com",
        "https://checkip.amazonaws.com",
    )

    # ---------- 工厂 ----------

    @classmethod
    def from_env(cls, *, base_dir: Path | None = None) -> "RuntimeConfig":
        cfg = cls()
        if base_dir is not None:
            cfg.base_dir = base_dir
            cfg.data_dir = base_dir / "data"

        env = os.environ

        def _g(name: str, default: str) -> str:
            return env.get(name, default)

        def _gb(name: str, default: bool) -> bool:
            v = env.get(name)
            if v is None:
                return default
            return v.strip().lower() in ("1", "true", "yes", "on")

        cfg.max_scan = safe_int(env.get("ORIONVM_MAX_SCAN"), cfg.max_scan)
        cfg.top_n = safe_int(env.get("ORIONVM_TOP"), cfg.top_n)
        cfg.workers = safe_int(env.get("ORIONVM_WORKERS"), cfg.workers)
        cfg.refresh_interval = safe_int(env.get("ORIONVM_REFRESH"), cfg.refresh_interval)
        cfg.iface_phys = _g("ORIONVM_IFACE_PHY", cfg.iface_phys)
        cfg.iface_vpn = _g("ORIONVM_IFACE_VPN", cfg.iface_vpn)
        cfg.auto_firewall = _gb("ORIONVM_FIREWALL", cfg.auto_firewall)
        mode = _g("ORIONVM_MODE", cfg.underway_mode)
        if mode in ("full", "out"):
            cfg.underway_mode = mode  # type: ignore[assignment]
        cfg.pid_file = Path(_g("ORIONVM_PID", str(cfg.data_dir / "daemon.pid")))
        cfg.log_file = Path(_g("ORIONVM_LOG", str(cfg.data_dir / "daemon.log")))
        if env.get("ORIONVM_DATA_DIR"):
            cfg.data_dir = Path(env["ORIONVM_DATA_DIR"])
            cfg.pid_file = cfg.data_dir / "daemon.pid"
            cfg.log_file = cfg.data_dir / "daemon.log"
        return cfg

    # ---------- helpers ----------

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        for p in (self.pid_file, self.log_file):
            p.parent.mkdir(parents=True, exist_ok=True)


__all__ = ["Mode", "RuntimeConfig"]
