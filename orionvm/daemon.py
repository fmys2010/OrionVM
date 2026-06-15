"""OrionVM 守护进程 —— 长时运行的节点刷新 + VPN 切换 + 防火墙编排.

调用:
    python -m orionvm --start         启动守护进程 (后台运行)
    python -m orionvm --stop          回收防火墙, 写最终状态.
    python -m orionvm --restart       重启守护进程

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
        self.blacklist: dict[str, float] = {}  # ip -> expire_timestamp

    def is_blacklisted(self, ip: str) -> bool:
        """Check if an IP is currently blacklisted."""
        if ip in self.blacklist:
            if time.time() < self.blacklist[ip]:
                return True
            # expired, remove
            del self.blacklist[ip]
        return False

    def add_to_blacklist(self, ip: str, duration_seconds: int = 1800) -> None:
        """Add an IP to blacklist for specified duration (default 30 min)."""
        self.blacklist[ip] = time.time() + duration_seconds

    def clean_blacklist(self) -> int:
        """Remove expired entries, return count of remaining."""
        now = time.time()
        expired = [ip for ip, ts in self.blacklist.items() if ts < now]
        for ip in expired:
            del self.blacklist[ip]
        return len(self.blacklist)


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
    from .pipeline import PipelineConfig
    pcfg = PipelineConfig(
        max_rows=int(getattr(cfg, "max_scan", 80)),
        probe_workers=int(getattr(cfg, "workers", 16)),
        geo_workers=int(getattr(cfg, "workers", 16)),
        run_geo=bool(getattr(cfg, "run_geo", True)),
    )
    return Pipeline(config=pcfg, logger=log)


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


def _discover_ovpn(top_node: Node) -> str | None:
    """Best-effort discover full OpenVPN config text for *top_node*."""
    # 1. Prefer inline raw_config (decoded from base64 by Node.property)
    raw: str | None = getattr(top_node, "raw_config", None)
    if isinstance(raw, str) and raw.strip():
        return raw
    # 2. Fallback to openvpn_config_b64 directly
    b64: str = getattr(top_node, "openvpn_config_b64", "")
    if b64:
        try:
            import base64
            pad = "=" * ((-len(b64)) % 4)
            text = base64.b64decode(b64 + pad).decode("utf-8", errors="replace")
            if text.strip():
                return text
        except Exception:
            pass
    # 3. Fallback to disk-cached .ovpn files
    candidates = [
        Path(f"/root/OrionVM/data/{top_node.id or top_node.ip}.ovpn"),
        Path("/root/OrionVM/data/node.ovpn"),
        Path("/tmp/orionvm.ovpn"),
    ]
    for p in candidates:
        try:
            if p.exists():
                text = p.read_text(encoding="utf-8", errors="replace")
                if text.strip():
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

    # Clean expired blacklist entries
    remaining = state.clean_blacklist()
    if remaining > 0:
        log.info(f"blacklist: {remaining} IPs currently blocked")

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

    # Filter out blacklisted nodes
    filtered = [n for n in ranked if not state.is_blacklisted(n.ip)]
    if not filtered:
        log.warning("all ranked nodes are blacklisted, will retry after backoff")
        return False

    log.info(f"ranked {len(ranked)} nodes, {len(filtered)} available after blacklist filter")

    # Try top nodes in order (up to 5)
    max_attempts = min(5, len(filtered))
    attempted = []

    for attempt_idx in range(max_attempts):
        top = filtered[attempt_idx]
        top_latency = top.probe.latency_ms if top.probe else 0
        top_score = score_node(top).score
        log.info(
            f"attempting #{attempt_idx + 1}: {top.ip} ({top.country_code}, "
            f"score={top_score:.1f}, lat={top_latency:.0f}ms)"
        )

        # ---- 2. Discover OpenVPN config text ----
        cfg_text = _discover_ovpn(top)
        if not cfg_text:
            log.error(f"{top.ip} has no .ovpn config, skipping")
            attempted.append(top.ip)
            continue

        # ---- 3. Start OpenVPN ----
        manager = OVPNManager(
            ovpn_path=cfg.ovpn_path,
            ovpn_log=cfg.ovpn_log,
            connect_timeout=cfg.connect_timeout,
            log=log,
        )
        state.ovpn = manager

        mode = "out" if cfg.underway_mode == "out" else "full"
        result: OVPNResult = manager.start(cfg_text, mode)
        if result.started:
            # Success!
            state.current_node = top
            state.current_exit_ip = result.exit_ip
            log.info(f"connected via {top.ip}, exit_ip={result.exit_ip or 'unknown'}")

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

        # Connection failed
        log.warning(f"takeover failed for {top.ip}: {result.msg}")
        state.ovpn = None
        attempted.append(top.ip)

    # All attempts failed, add all attempted IPs to blacklist
    log.error(f"all {len(attempted)} connection attempts failed, adding to blacklist (30min)")
    for ip in attempted:
        state.add_to_blacklist(ip, duration_seconds=1800)

    return False


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
