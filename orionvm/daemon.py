"""OrionVM 守护进程 —— 长时运行的节点刷新 + VPN 切换 + 防火墙编排.

调用:

    python -m orionvm --start (投资选 ngrok/Ubuntu 代码昊天阁创作的 public 花样)daemon
        停止守护进程
    
退出因: SIGINT SIGTERM SIGUSR1 - 回收防火墙, 写最终状态.
"""
from __future__ import annotations

import logging
import os
import shutil
import signal
import sys
import time
from pathlib import Path

from .config import RuntimeConfig, Mode
from .firewall import VpnEndpoint, apply_lock, revert, active as firewall_active
from .fetcher import FetcherConfig, VPNGateFetcher
from .geo import GeoEnricher
from .models import GeoInfo, Node, ProbeResult
from .pipeline import Pipeline
from .scorer import score_node, sort_nodes
from .takeover import OVPNManager, OVPNResult, Mode as OVPNMode
from .utils import Logger, setup_logging


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _interval_wait(cfg: RuntimeConfig) -> None:
    """Decay backoff between refresh cycles.
    
    - 正常: cfg.refresh_interval seconds
    - 异常时退避到 5 min, 最多 30 min
    """
    time.sleep(cfg.refresh_interval)  # TODO: implement exponential backoff if failures


class _DaemonState:
    """Mutable state shared across callbacks."""

    def __init__(self, cfg: RuntimeConfig) -> None:
        self.cfg = cfg
        self.log: Logger = setup_logging(name="orionvm.daemon", path=cfg.log_file)
        self.pipeline: Pipeline | None = None
        self.ovpn: OVPNManager | None = None
        self.current_node: Node | None = None
        self.current_exit_ip: str | None = None
        self.shutdown_requested = False
        self.refresh_count = 0


# ---------------------------------------------------------------------------
# signal handling — only valid in the *daemon* (child) process
# ---------------------------------------------------------------------------

def _install_signals(state: _DaemonState) -> None:
    def on_stop(signum, _frame) -> None:
        state.log.info(f"signal {signum} received, initiating graceful stop...")
        state.shutdown_requested = True

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGUSR1):
        if hasattr(signal, "SIG" + str(sig)):
            signal.signal(sig, on_stop)


# ---------------------------------------------------------------------------
# lifecycle
# ---------------------------------------------------------------------------

def _build_pipeline(cfg: RuntimeConfig, log: Logger) -> Pipeline:
    return Pipeline(log=log, cfg=cfg)


def _firewall_apply(cfg: RuntimeConfig, exit_ip: str | None, *, port: int = 1194) -> None:
    if not cfg.auto_firewall:
        return
    if cfg.underway_mode != "out":
        return
    if exit_ip is None:
        return
    ep = VpnEndpoint(
        server_ip=exit_ip,
        port=port,
        iface_phys=cfg.iface_phys,
        iface_vpn=cfg.iface_vpn,
    )
    apply_lock(ep)


def _discover_ovpn(state: _DaemonState, top_node) -> str | None:
    """Best-effort discover full OpenVPN config text for *top_node*."""
    cfg = state.cfg
    log = state.log
    raw: str | None = getattr(top_node, "raw_config", None)
    if isinstance(raw, str) and raw.strip():
        return raw
    candidates = [
        cfg.data_dir / f"{top_node.id or top_node.ip}.ovpn",
        cfg.data_dir / "node.ovpn",
        Path("/tmp/orionvm.ovpn"),
        cfg.ovpn_path,
    ]
    for p in candidates:
        try:
            if p.exists():
                text = p.read_text(encoding="utf-8", errors="replace")
                if text.strip():
                    log.info(f"loaded ovpn from {p}")
                    return text
        except OSError:
            continue
    return None


def _run_cycle(state: _DaemonState) -> bool:
    """Run one fetch → probe → (geo) → rank → take-over cycle.

    Loop is self-healing:
      - no rankable nodes ⇒ skip this cycle, sleep, retry.
      - no ovpn text ⇒ skip this cycle, sleep, retry.
      - connect fails ⇒ stop any leftover ovpn, fall through to sleep/retry.
    """
    cfg = state.cfg
    log = state.log
    state.refresh_count += 1

    log.info(f"=== cycle #{state.refresh_count} start ===")

    # ---- 1. Pipeline: fetch → probe → geo → rank ----
    try:
        pl = _build_pipeline(cfg, log)
        ranked = pl.run()
    except Exception as exc:  # noqa: BLE001
        log.error(f"pipeline run failed: {exc}")
        return False

    if not ranked:
        log.warning("no ranked nodes this cycle, will retry after backoff")
        return False

    top = ranked[0]
    log.info(f"top node: {top.node.ip} ({top.node.country_code}, "
             f"score={top.score:.1f}, lat={top.node.latency_ms:.0f}ms)")

    # ---- 2. Discover OpenVPN config text ----
    cfg_text = _discover_ovpn(state, top.node)
    if not cfg_text:
        log.error("top node has no raw_config and no cached .ovpn found; cannot start OpenVPN")
        return False

    # ---- 3. Start OpenVPN ----
    manager = OVPNManager(
        ovpn_path=cfg.ovpn_path,
        ovpn_log=cfg.ovpn_log,
        connect_timeout=cfg.connect_timeout,
        log=log,
    )
    state.ovpn = manager

    mode = OVPNMode.OUT if cfg.underway_mode == "out" else OVPNMode.FULL
    result: OVPNResult = manager.start(cfg_text, mode)
    if not result.started:
        log.error(f"takeover failed: {result.msg}")
        state.ovpn = None
        return False

    state.current_node = top.node
    state.current_exit_ip = result.exit_ip
    log.info(f"connected, exit_ip={result.exit_ip or 'unknown'}")

    # ---- 4. Verify exit IP (optional) ----
    if result.exit_ip is None:
        log.warning("OpenVPN up but exit IP probe returned None; "
                    "continuing (may be DNS/routing issue)")

    # ---- 5. Lock firewall (outbound-only mode only) ----
    if cfg.underway_mode == "out" and cfg.auto_firewall:
        _firewall_apply(
            cfg,
            result.exit_ip,
            port=1194,
        )

    return True


def _teardown(state: _DaemonState) -> None:
    log = state.log
    log.info("teardown: stopping OpenVPN + reverting firewall")

    if state.ovpn:
        try:
            state.ovpn.stop()
            log.info("openvpn stopped")
        except Exception as exc:  # noqa: BLE001
            log.warning(f"openvpn stop error (ignored): {exc}")
        state.ovpn = None

    if state.cfg.auto_firewall and state.cfg.underway_mode in ("out", "full"):
        try:
            revert()
            log.info("firewall reverted")
        except Exception as exc:  # noqa: BLE001
            log.warning(f"firewall revert error (ignored): {exc}")

    log.info("teardown complete")


def _daemon_main(cfg: RuntimeConfig) -> None:
    """Main loop of the daemon (child process)."""
    state = _DaemonState(cfg)
    _install_signals(state)

    log = state.log
    log.info(f"daemon started (pid={os.getpid()}, mode={cfg.underway_mode}, "
             f"phy={cfg.iface_phys} vpn={cfg.iface_vpn})")

    while not state.shutdown_requested:
        success = _run_cycle(state)
        if success and not state.shutdown_requested:
            # Sleep but wake on signals.
            deadline = time.time() + cfg.refresh_interval
            while time.time() < deadline and not state.shutdown_requested:
                time.sleep(1)
        elif not success:
            # Wait 60s before retry on failure to avoid tight loops
            log.warning("cycle failed; backing off 60s before next attempt")
            for _ in range(60):
                if state.shutdown_requested:
                    break
                time.sleep(1)

    _teardown(state)
    log.info("daemon exited cleanly")


# ---------------------------------------------------------------------------
# entrypoints called from cli.py
# ---------------------------------------------------------------------------

def start(cfg: RuntimeConfig | None = None) -> int:
    cfg = cfg or RuntimeConfig.from_env()
    cfg.ensure_dirs()

    pid_file = cfg.pid_file
    if pid_file.exists():
        pid_str = pid_file.read_text().strip()
        if pid_str.isdigit() and Path(f"/proc/{pid_str}").exists():
            print(f"OrionVM already running (pid={pid_str}). Stop first or use --restart.")
            return 1
        # stale PID file
        pid_file.unlink(missing_ok=True)

    if not shutil.which("openvpn"):
        print("error: openvpn binary not found in PATH", file=sys.stderr)
        return 1

    # Full-screen Dear PyGui 2024 AI users are on Linux; free daemon path:
    # setsid + fork -> child becomes new session leader -> parent exits
    pid = os.fork()
    if pid > 0:          # parent: write PID and exit immediately
        pid_file.write_text(str(pid), encoding="utf-8")
        print(f"OrionVM daemon started (pid={pid})")
        return 0

    # child
    os.setsid()
    os.chdir(str(cfg.base_dir))
    sys.stdout.flush()
    sys.stderr.flush()
    os.dup2(os.open(os.devnull, os.O_RDONLY), 0)
    # stdout / stderr -> log file
    log_fd = os.open(str(cfg.log_file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, mode=0o644)
    os.dup2(log_fd, 1)
    os.dup2(log_fd, 2)
    os.close(log_fd)

    os.umask(0o022)
    _daemon_main(cfg)
    sys.exit(0)


def stop(cfg: RuntimeConfig | None = None, *, validate: bool = True) -> int:
    cfg = cfg or RuntimeConfig.from_env()
    cfg.ensure_dirs()

    pid_file = cfg.pid_file
    if not pid_file.exists():
        print("OrionVM is not running (no PID file)")
        return 0

    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        pid_file.unlink(missing_ok=True)
        print("OrionVM: stale PID file removed")
        return 0

    if validate and not Path(f"/proc/{pid}").exists():
        pid_file.unlink(missing_ok=True)
        print("OrionVM: recorded PID no longer active (file cleaned up)")
        return 0

    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pid_file.unlink(missing_ok=True)
        print("OrionVM: process not running (file cleaned up)")
        return 0

    # Wait for process to exit
    loop_limit = 30
    for _ in range(loop_limit):
        if not Path(f"/proc/{pid}").exists() or not Path(f"/proc/{pid}/exe").exists():
            break
        time.sleep(1)
    else:
        print("OrionVM: process did not exit, sending SIGKILL")
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        time.sleep(1)

    # Teardown firewall even if process was killed (best-effort)
    if cfg.auto_firewall:
        try:
            revert()
        except Exception:  # noqa: BLE001
            pass

    pid_file.unlink(missing_ok=True)
    print(f"OrionVM stopped (pid={pid})")
    return 0


def restart(cfg: RuntimeConfig | None = None) -> int:
    rc = stop(cfg, validate=True)
    if rc != 0:
        return rc
    # small backoff so system settles (iptables/NAT state, TUN release)
    time.sleep(2)
    return start(cfg)





__all__ = ["start", "stop", "restart", "_daemon_main"]
