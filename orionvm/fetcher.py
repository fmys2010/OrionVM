"""OrionVM 节点获取 —— 从 VPNGate API 拉取并结构化."""
from __future__ import annotations

import base64
import csv
import gzip
import json
import ssl
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Iterable

from .models import Node
from .utils import (
    parse_openvpn_remote,
    retry,
    safe_int,
)


@dataclass(slots=True)
class FetcherConfig:
    max_rows: int = 100
    timeout: float = 25.0
    retries: int = 2
    cache_path: Path | None = None  # 写一份 JSON 缓存


# 主源 + 备用源, 实测时按顺序尝试
DEFAULT_ENDPOINTS: tuple[str, ...] = (
    "https://www.vpngate.net/api/iphone/",
    "http://www.vpngate.net/api/iphone/",
)


class VPNGateFetcher:
    """从 VPNGate iOS 端点拉取 CSV, 解码 OpenVPN 配置, 输出 Node 列表."""

    HEADERS = {
        "User-Agent": "orionvm/0.2 (+https://github.com/fmys2010)",
        "Accept": "text/csv,text/plain;q=0.9,*/*;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }

    def __init__(self, config: FetcherConfig | None = None) -> None:
        self.config = config or FetcherConfig()

    # ----- public -----

    def fetch(self) -> list[Node]:
        """取节点, 失败时回退到磁盘缓存 (可选)."""
        raw_csv = self._fetch_raw()
        if not raw_csv:
            return self._load_cache()
        nodes = self._parse_csv(raw_csv)
        if self.config.cache_path and nodes:
            self._save_cache(nodes)
        return nodes

    # ----- transport -----

    @retry(attempts=2, delay=1.0)
    def _fetch_raw(self) -> str:
        last_err: Exception | None = None
        for url in DEFAULT_ENDPOINTS:
            for verify in (True, False):
                try:
                    return self._get(url, verify_ssl=verify)
                except Exception as e:
                    last_err = e
                    continue
        if last_err is not None:
            raise last_err
        return ""

    def _get(self, url: str, verify_ssl: bool) -> str:
        ctx: ssl.SSLContext | None = None
        if not verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers=self.HEADERS)
        with urllib.request.urlopen(req, context=ctx, timeout=self.config.timeout) as resp:
            raw = resp.read()
            encoding = (resp.headers.get("Content-Encoding") or "").lower()
            if encoding == "gzip" or raw[:2] == b"\x1f\x8b":
                try:
                    raw = gzip.decompress(raw)
                except OSError:
                    pass
            try:
                return raw.decode("utf-8", errors="replace")
            except Exception:
                return raw.decode("latin-1", errors="replace")

    # ----- parsing -----

    def _parse_csv(self, text: str) -> list[Node]:
        # 第 1 行是 *vpn_servers 注释, 第 2 行是字段名 (以 # 开头)
        lines = [
            ln for ln in (l.strip() for l in text.splitlines())
            if ln and not ln.startswith("*")
        ]
        if len(lines) < 2:
            return []
        header_line = lines[0].lstrip("#")
        fieldnames = [f.strip() for f in header_line.split(",")]
        body = lines[1 : 1 + self.config.max_rows]

        reader = csv.DictReader(StringIO("\n".join(body)), fieldnames=fieldnames)
        nodes: list[Node] = []
        seen_ids: set[str] = set()
        for row in reader:
            node = self._row_to_node(row)
            if node is None:
                continue
            if node.id in seen_ids:
                continue
            seen_ids.add(node.id)
            nodes.append(node)
        return nodes

    def _row_to_node(self, row: dict[str, str]) -> Node | None:
        try:
            hostname = (row.get("#HostName") or row.get("HostName") or "").strip()
            ip = (row.get("IP") or "").strip()
            if not ip:
                return None
            country_long = (row.get("CountryLong") or row.get("Country") or "").strip()
            country_short = (row.get("CountryShort") or "").strip().upper()
            score = safe_int(row.get("Score"))
            speed = safe_int(row.get("Speed"))
            ping = safe_int(row.get("Ping"))
            sessions = safe_int(row.get("NumVpnSessions"))
            uptime = safe_int(row.get("DaysRunning") or row.get("Uptime"))
            log_type = (row.get("LogType") or "").strip()
            operator = (row.get("Operator") or "").strip()
            operator_msg = (row.get("Message") or "").strip()
            config_b64 = (row.get("OpenVPN_ConfigData_Base64") or "").strip()

            remote_host = ip
            remote_port = 0
            proto = "tcp"
            config_text = ""
            if config_b64:
                try:
                    pad = "=" * (-len(config_b64) % 4)
                    config_text = base64.b64decode(config_b64 + pad).decode("utf-8", errors="replace")
                except Exception:
                    config_text = ""
                if config_text:
                    h, p, proto_ = parse_openvpn_remote(config_text)
                    if h:
                        remote_host = h
                    if p:
                        remote_port = p
                    if proto_ and proto_ != "unknown":
                        proto = proto_

            node_id = f"{country_short or 'XX'}_{ip}_{remote_port or 0}_{proto}"
            return Node(
                id=node_id,
                ip=ip,
                hostname=hostname,
                country=country_long,
                country_code=country_short,
                operator=operator,
                score=score,
                speed_bps=speed,
                sessions=sessions,
                uptime_days=uptime,
                log_type=log_type,
                operator_msg=operator_msg,
                remote_host=remote_host,
                remote_port=remote_port,
                protocol=proto,
                openvpn_config_b64=config_b64,
                fetched_at=time.time(),
            )
        except Exception:
            return None

    # ----- cache -----

    def _load_cache(self) -> list[Node]:
        if not self.config.cache_path:
            return []
        if not self.config.cache_path.exists():
            return []
        try:
            data = json.loads(self.config.cache_path.read_text(encoding="utf-8"))
            return [Node.from_dict(d) for d in data if isinstance(d, dict)]
        except Exception:
            return []

    def _save_cache(self, nodes: list[Node]) -> None:
        if not self.config.cache_path:
            return
        self.config.cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = [n.to_dict() for n in nodes]
        self.config.cache_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


__all__ = ["FetcherConfig", "VPNGateFetcher"]
