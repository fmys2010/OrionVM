"""OrionVM 节点质量探测 —— TCP 握手 / ICMP ping / banner 解析."""
from __future__ import annotations

import asyncio
import platform
import re
import socket
import statistics
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable

from .models import Node, ProbeResult
from .utils import is_ipv4


@dataclass(slots=True)
class ProbeConfig:
    timeout: float = 6.0
    tcp_retries: int = 3
    icmp_count: int = 3
    workers: int = 16
    probe_banner: bool = False  # 抓首行 banner, 二次确认服务真在跑


@dataclass(slots=True)
class ProbeReport:
    node: Node
    result: ProbeResult

    @property
    def passed(self) -> bool:
        return self.result.alive and self.result.latency_ms > 0


class NodeProbe:
    """单节点质量探测 (TCP 握手 + 可选 ICMP + 可选 banner 嗅探)."""

    def __init__(self, config: ProbeConfig | None = None) -> None:
        self.config = config or ProbeConfig()

    # ---- TCP 握手延迟 ----

    def tcp_latency(self, host: str, port: int) -> tuple[int, float]:
        """多次 TCP 三次握手, 返回 (中位数 ms, 失败率)."""
        if not host or port <= 0:
            return 0, 1.0
        af = socket.AF_INET6 if ":" in host else socket.AF_INET
        latencies: list[int] = []
        failures = 0

        for _ in range(self.config.tcp_retries):
            started = time.perf_counter()
            sock = None
            try:
                sock = socket.socket(af, socket.SOCK_STREAM)
                sock.settimeout(self.config.timeout)
                sock.connect((host, port))
                elapsed_ms = (time.perf_counter() - started) * 1000.0
                latencies.append(max(1, int(elapsed_ms)))
            except (OSError, socket.timeout):
                failures += 1
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

        if not latencies:
            return 0, 1.0

        median = int(statistics.median(latencies))
        loss = failures / max(1, failures + len(latencies))
        return median, loss

    # ---- ICMP ping ----

    def icmp_latency(self, host: str) -> int | None:
        """调用系统 ping, 解析平均延迟. 返回 None 表示不可用."""
        if not host:
            return None
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", str(self.config.icmp_count), "-w", "3000", host]
            creationflags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
            kwargs: dict = {
                "capture_output": True,
                "text": True,
                "timeout": self.config.icmp_count * 4 + 2,
                "creationflags": creationflags,
            }
        else:
            cmd = ["ping", "-c", str(self.config.icmp_count), "-W", "3", host]
            kwargs = {
                "capture_output": True,
                "text": True,
                "timeout": self.config.icmp_count * 4 + 2,
            }
        try:
            r = subprocess.run(cmd, **kwargs)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
        if r.returncode != 0:
            return None

        out = r.stdout
        m = re.search(r"[Aa]verage\s*=\s*(\d+)\s*ms", out)  # Windows en
        if not m:
            m = re.search(r"平均\s*[=~]\s*(\d+)\s*ms", out)  # Windows zh
        if not m:
            m = re.search(r"min/avg/max[/\w]*\s*=\s*[\d.]+/([\d.]+)/", out)  # Linux/macOS
        if not m:
            return None
        return int(float(m.group(1)))

    # ---- 可选 banner sniff ----

    def sniff_banner(self, host: str, port: int) -> str:
        """读首 64 字节, 用于二次确认服务存活."""
        if not host or port <= 0:
            return ""
        af = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = None
        try:
            sock = socket.socket(af, socket.SOCK_STREAM)
            sock.settimeout(min(self.config.timeout, 4.0))
            sock.connect((host, port))
            sock.settimeout(2.0)
            data = sock.recv(128)
            return data[:64].decode("ascii", errors="replace").strip()
        except OSError:
            return ""
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    # ---- 主入口 ----

    def probe(self, node: Node) -> ProbeReport:
        host = node.remote_host or node.ip
        port = int(node.remote_port or 0)
        result = ProbeResult()

        icmp = self.icmp_latency(host) if is_ipv4(host) and platform.system() != "Windows" or True else None
        # 跨平台: 都先尝试 ICMP; 失败才回退 TCP
        icmp_ms = self.icmp_latency(host)
        result.icmp_rtt_ms = icmp_ms or 0

        tcp_ms, loss = self.tcp_latency(host, port)
        result.tcp_rtt_ms = tcp_ms
        result.loss_pct = round(loss * 100.0, 1)

        # 综合延迟: 优先 ICMP, 缺失则用 TCP
        if icmp_ms and icmp_ms > 0:
            result.latency_ms = icmp_ms
        else:
            result.latency_ms = tcp_ms

        if tcp_ms <= 0:
            result.alive = False
            result.error = "tcp_unreachable"
        else:
            result.alive = True
            # jitter = max - min in TCP attempts; 简化用 stddev
            samples: list[int] = []
            for _ in range(self.config.tcp_retries):
                t, _ = self.tcp_latency(host, port)
                if t > 0:
                    samples.append(t)
            if len(samples) >= 2:
                result.jitter_ms = max(1, int(statistics.pstdev(samples)))

        # 可选 banner, 仅当 alive 时执行
        if self.config.probe_banner and result.alive:
            banner = self.sniff_banner(host, port)
            if banner and not re.search(r"(openvpn|softether|packetix)", banner, re.IGNORECASE):
                # banner 不像代理协议, 视作不可信
                result.error = f"unexpected_banner:{banner[:32]}"
                result.alive = False

        node.probe = result
        node.probed_at = time.time()
        return ProbeReport(node=node, result=result)

    # ---- 并发批量 ----

    def probe_many(
        self,
        nodes: list[Node],
        on_progress: Callable[[int, int, ProbeReport], None] | None = None,
    ) -> list[ProbeReport]:
        reports: list[ProbeReport] = []
        if not nodes:
            return reports
        total = len(nodes)
        workers = min(self.config.workers, total)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.probe, n): n for n in nodes}
            done = 0
            for fut in as_completed(futures):
                done += 1
                try:
                    rpt = fut.result()
                except Exception as e:
                    n = futures[fut]
                    n.probe = ProbeResult(alive=False, error=f"probe_exception:{e}")
                    rpt = ProbeReport(node=n, result=n.probe)
                reports.append(rpt)
                if on_progress:
                    on_progress(done, total, rpt)
        return reports


__all__ = ["ProbeConfig", "ProbeReport", "NodeProbe"]
