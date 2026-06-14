"""OrionVM CLI —— 节点获取/测速 + VPN 接管 + 防火墙 + 后台守护.

入口: python -m orionvm [subcommand] [opts]

Subcommands
-----------
  scan     单次抓取 + 探测 + 排序, 输出至 stdout, 不启动 VPN  (默认子命令)
  start    启动守护进程 (后台异步抓取 → 连接最优节点 → 接管网络)
  stop     停止守护进程 (SIGTERM + 防火墙回收)
  restart  重启挂接
  status   当前 daemon 状态 (PID/运维间隔/最近日志/出口 IP)
  log      tail -f 日志文件 (或 --log 指定)

模式 (仅 start/restart 生效)
  --full               双向接管 (default/原行为)
  --out                只接管出站 (Linux redirect-gateway local + iptables)
  --iface-phy NAME     物理网卡 (default eth0)
  --iface-vpn NAME     VPN 网卡 (default tun0)

扫描参数 (默认 & --scan 子命令)
  --max-scan N         抓取上限 (default 80)
  --workers N          并发探测工作线程 (default 16)
  --no-geo             跳过 IP 质量检测
  --top N              输出前 N 条 (default 20)

其他
  --ovpn FILE          .ovpn 文件路径 (start 必需)
  --data-dir DIR       数据目录 (default ./data)
  --log FILE           日志文件 (PATH)   [仅 log 子命令 & daemon 输出]
"""
from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path
from typing import List, Optional

from .config import RuntimeConfig, Mode
from .daemon import start as daemon_start, stop as daemon_stop, restart as daemon_restart
from .pipeline import Pipeline
from .utils import Logger, setup_logging


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_runtime(args: argparse.Namespace) -> RuntimeConfig:
    cfg = RuntimeConfig.from_env()
    # Override from CLI
    if getattr(args, "data_dir", None):
        cfg.data_dir = Path(args.data_dir)
        cfg.pid_file = cfg.data_dir / "daemon.pid"
        cfg.log_file = cfg.data_dir / "daemon.log"
    if getattr(args, "max_scan", None) is not None:
        cfg.max_scan = args.max_scan
    if getattr(args, "workers", None) is not None:
        cfg.workers = args.workers
    if getattr(args, "no_geo", False):
        cfg.run_geo = False  # PipelineConfig field
    if getattr(args, "top", None) is not None:
        cfg.top_n = args.top
    if getattr(args, "iface_phy", None):
        cfg.iface_phys = args.iface_phy
    if getattr(args, "iface_vpn", None):
        cfg.iface_vpn = args.iface_vpn
    if getattr(args, "mode", None) in ("out", "full"):
        cfg.underway_mode = args.mode  # type: ignore[assignment]
    if getattr(args, "log", None):
        cfg.log_file = Path(args.log)
    cfg.ensure_dirs()
    return cfg


# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    cfg = _make_runtime(args)
    cfg.run_geo = not getattr(args, "no_geo", False)
    from .pipeline import Pipeline, PipelineConfig
    log = setup_logging(name="orionvm.scan", path=getattr(args, "log", None))
    pcfg = PipelineConfig(
        max_rows=cfg.max_scan,
        probe_workers=cfg.workers,
        run_geo=cfg.run_geo,
    )
    pipe = Pipeline(config=pcfg, logger=log)
    results = pipe.run()
    if not results:
        log.warning("no nodes")
        return 1
    # print_top helper
    from .scorer import sort_nodes
    from .models import Node
    top = sorted(results, key=lambda n: (0 if n.probe and n.probe.alive else 1, n.probe.latency_ms if n.probe else 9999))[:min(cfg.top_n, len(results))]
    for rank, n in enumerate(top, 1):
        lat = n.probe.latency_ms if n.probe else 0
        alive = "yes" if (n.probe and n.probe.alive) else "NO"
        log.info(f"{rank} {n.ip:<20} {n.country_code:<3} {lat}ms {alive}")
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    cfg = _make_runtime(args)
    # 用户通过 --ovpn 显式指定时才做存在性检查；默认路径留到 daemon 内部回退。
    explicit_ovpn = getattr(args, "ovpn", None)
    if explicit_ovpn:
        p = Path(explicit_ovpn)
        if not p.exists():
            print(f"error: --ovpn file not found: {p}", file=sys.stderr)
            return 1
        cfg.ovpn_path = p
    print("orionvm start: auto scan → rank → connect → lock")
    return daemon_start(cfg)


def cmd_stop(args: argparse.Namespace) -> int:
    return daemon_stop(_make_runtime(args))


def cmd_restart(args: argparse.Namespace) -> int:
    return daemon_restart(_make_runtime(args))


def cmd_status(args: argparse.Namespace) -> int:
    cfg = _make_runtime(args)
    pid_file = cfg.pid_file
    if not pid_file.exists():
        print("OrionVM: not running (no PID file)")
        return 1
    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        print("OrionVM: corrupt PID file, removing")
        pid_file.unlink(missing_ok=True)
        return 1

    alive = Path(f"/proc/{pid}").exists()
    print(f"OrionVM pid={pid}  {'RUNNING' if alive else 'DEAD'}")
    if cfg.log_file.exists():
        print("--- log tail (last 30 lines) ---")
        lines = cfg.log_file.read_text(errors="replace").splitlines()[-30:]
        for ln in lines:
            print(ln)
    return 0


def cmd_log(args: argparse.Namespace) -> int:
    cfg = _make_runtime(args)
    log_path = cfg.log_file
    if not log_path.exists():
        print(f"log file not found: {log_path}", file=sys.stderr)
        return 1
    follow = getattr(args, "follow", False)
    if follow:
        if not shutil.which("tail"):
            print("tail not found, cannot follow", file=sys.stderr)
            return 1
        # run tail -f as child of this process so Ctrl-C stops it
        import subprocess
        subprocess.run(["tail", "-f", str(log_path)])
        return 0
    # plain tail
    lines = log_path.read_text(errors="replace").splitlines()[-100:]
    for ln in lines:
        print(ln)
    return 0


# ---------------------------------------------------------------------------
# argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="orionvm",
        description="OrionVM — 节点获取・质量评估・VPN 自动接管",
    )
    p.add_argument("--data-dir", default=None, help="数据目录 (default ./data)")
    p.add_argument("--log", default=None, help="日志文件路径或 tail 目标")

    # Mode flags (subsumed by daemon)
    p.add_argument(
        "--out", "--outbound-only", dest="mode", action="store_const", const="out",
        help="只接管出站 (Linux redirect-gateway local + iptables)",
    )
    p.add_argument(
        "--full", dest="mode", action="store_const", const="full",
        help="双向接管 (default)",
    )
    p.add_argument("--iface-phy", default=None, help="物理网卡名 (default eth0)")
    p.add_argument("--iface-vpn", default=None, help="VPN 网卡名 (default tun0)")
    p.add_argument("--ovpn", default=None, help="OpenVPN 配置文件路径 (start/restart 使用)")
    p.add_argument("--no-geo", action="store_true", help="跳过 IP 质量检测")

    sub = p.add_subparsers(dest="command", metavar="<command>")

    # scan
    sp_scan = sub.add_parser("scan", help="单次抓取 + 探测 + 排序 (不接管)")
    sp_scan.add_argument("--max-scan", type=int, default=None, metavar="N")
    sp_scan.add_argument("--workers", type=int, default=None, metavar="N")
    sp_scan.add_argument("--top", type=int, default=None, metavar="N")

    sp_start = sub.add_parser("start", help="启动守护进程")
    sp_start.add_argument("--max-scan", type=int, default=None, metavar="N")
    sp_start.add_argument("--workers", type=int, default=None, metavar="N")
    sp_start.add_argument("--top", type=int, default=None, metavar="N")
    sp_start.add_argument("--ovpn", default=None, help="OpenVPN .ovpn 配置文件路径 (start/restart 必需)")

    # stop
    sub.add_parser("stop", help="停止守护进程")

    sp_restart = sub.add_parser("restart", help="重启守护进程")
    sp_restart.add_argument("--max-scan", type=int, default=None, metavar="N")
    sp_restart.add_argument("--workers", type=int, default=None, metavar="N")
    sp_restart.add_argument("--top", type=int, default=None, metavar="N")
    sp_restart.add_argument("--ovpn", default=None, help="OpenVPN .ovpn 配置文件路径")

    # status
    sub.add_parser("status", help="显示当前 daemon 状态")

    # log
    sp_log = sub.add_parser("log", help="查看/跟随 daemon 日志")
    sp_log.add_argument("-f", "--follow", action="store_true", help="follow mode (tail -f)")

    # default: scan if nothing given
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # If no subcommand given, default to scan
    if args.command is None:
        args.command = "scan"

    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "start":
        return cmd_start(args)
    if args.command == "stop":
        return cmd_stop(args)
    if args.command == "restart":
        return cmd_restart(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "log":
        return cmd_log(args)

    parser.print_help()
    return 1


__all__ = ["build_parser", "main"]
