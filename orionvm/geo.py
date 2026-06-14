"""OrionVM IP 地理与质量 —— ip-api (主) + ipinfo (备) 拼接."""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Iterable

from .models import GeoInfo, Node
from .utils import chunked, retry


@dataclass(slots=True)
class GeoConfig:
    timeout: float = 8.0
    batch_size: int = 80
    workers: int = 4
    throttle_seconds: float = 1.5  # 免费 ip-api 45 req/min
    cache_ttl_seconds: int = 7 * 24 * 3600
    user_agent: str = "orionvm/0.2"


# ---- 已知数据中心 ASN (粗匹配) ----
KNOWN_DC_ASNS: tuple[str, ...] = (
    "as14061",  # DigitalOcean
    "as16509",  # AWS
    "as15169",  # GCP
    "as8075",   # Azure
    "as63949",  # Linode
    "as20473",  # Vultr
    "as24940",  # Hetzner
    "as16276",  # OVH
    "as13335",  # Cloudflare
    "as20940",  # Akamai
    "as54113",  # Fastly
    "as132203", "as37963", "as45102",  # Tencent / Alibaba Cloud 亚洲段
)

HOSTING_KEYWORDS: tuple[str, ...] = (
    "hosting", "datacenter", "data center", "cloud", "vps",
    "server", "colo", "cdn", "vpn", "tor", "dedicated",
)


def _classify_by_text(hosting_flag: bool, mobile_flag: bool, proxy_flag: bool,
                      asn: str, org: str) -> str:
    text = f"{asn} {org}".lower()
    if any(dc in text for dc in KNOWN_DC_ASNS):
        return "datacenter"
    if mobile_flag:
        return "mobile"
    if proxy_flag:
        return "proxy"
    if hosting_flag or any(kw in text for kw in HOSTING_KEYWORDS):
        return "hosting"
    return "residential"


# ---- ip-api.com (主) ----

def _query_ipapi_batch(ips: list[str], cfg: GeoConfig, ctx_disabled: bool = False) -> dict[str, dict]:
    """https://ip-api.com 批量接口, 免费上限 100/批."""
    url = (
        "http://ip-api.com/batch?"
        "fields=status,message,country,countryCode,region,regionName,city,"
        "isp,org,as,asname,mobile,proxy,hosting,query"
    )
    if ctx_disabled:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = None
    payload = json.dumps(ips).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": cfg.user_agent,
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=cfg.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RuntimeError("ipapi_rate_limited")
        raise

    if not isinstance(data, list):
        raise RuntimeError("ipapi_bad_response")
    return {item.get("query", ""): item for item in data if isinstance(item, dict)}


def _parse_ipapi_item(item: dict) -> GeoInfo:
    if item.get("status") != "success":
        return GeoInfo()
    hosting = bool(item.get("hosting", False))
    mobile = bool(item.get("mobile", False))
    proxy = bool(item.get("proxy", False))
    asn = str(item.get("as") or "")
    org = str(item.get("org") or "")
    ip_type = _classify_by_text(hosting, mobile, proxy, asn, org)
    trust = {
        "residential": 90,
        "mobile": 75,
        "hosting": 45,
        "datacenter": 30,
        "proxy": 10,
    }.get(ip_type, 50)
    return GeoInfo(
        country=item.get("country", ""),
        country_code=item.get("countryCode", ""),
        region=item.get("regionName", ""),
        city=item.get("city", ""),
        isp=item.get("isp", ""),
        org=org,
        asn=asn,
        ip_type=ip_type,
        is_flagged=proxy,
        trust_score=trust,
    )


# ---- ipinfo.io (备) ----

def _query_ipinfo_one(ip: str, cfg: GeoConfig) -> GeoInfo:
    url = f"https://ipinfo.io/{ip}/json"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": cfg.user_agent, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return GeoInfo()
    org = str(data.get("org", ""))
    asn = org.split(" ", 1)[0] if org else ""
    lower = org.lower()
    if any(kw in lower for kw in HOSTING_KEYWORDS):
        ip_type = "datacenter"
    elif any(kw in lower for kw in ("broadband", "telecom", "cable", "fiber")):
        ip_type = "residential"
    else:
        ip_type = "unknown"
    return GeoInfo(
        country=data.get("country", ""),
        country_code=data.get("country", ""),
        region=data.get("region", ""),
        city=data.get("city", ""),
        isp="",
        org=org,
        asn=asn,
        ip_type=ip_type,
        trust_score=70 if ip_type == "residential" else 30 if ip_type == "datacenter" else 50,
    )


# ---- 编排 ----

class GeoEnricher:
    """批量 IP 地理与质量签名, 自动降级."""

    def __init__(self, config: GeoConfig | None = None) -> None:
        self.config = config or GeoConfig()
        self._last_req_ts = 0.0

    def _throttle(self) -> None:
        now = time.time()
        elapsed = now - self._last_req_ts
        if elapsed < self.config.throttle_seconds:
            time.sleep(self.config.throttle_seconds - elapsed)
        self._last_req_ts = time.time()

    def enrich(
        self,
        nodes: Iterable[Node],
        on_progress: Callable[[int, int], None] | None = None,
    ) -> None:
        node_list = list(nodes)
        unique_ips = list(dict.fromkeys(n.ip for n in node_list if n.ip))
        if not unique_ips:
            return
        total = len(unique_ips)
        info_map: dict[str, GeoInfo] = {}

        # ---- 主源 ip-api 批量 ----
        try:
            for chunk in chunked(unique_ips, self.config.batch_size):
                self._throttle()
                try:
                    raw_map = _query_ipapi_batch(chunk, self.config)
                except RuntimeError as e:
                    if "rate_limited" in str(e):
                        raise
                    raise
                for ip, item in raw_map.items():
                    info_map[ip] = _parse_ipapi_item(item)
                if on_progress:
                    on_progress(len(info_map), total)
        except Exception:
            info_map.clear()  # 主源失败, 全部降级备源

        # ---- 备源 ipinfo 并发补缺失 ----
        missing = [ip for ip in unique_ips if ip not in info_map]
        if missing:
            workers = min(self.config.workers, max(1, len(missing)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(_query_ipinfo_one, ip, self.config): ip for ip in missing}
                for fut in as_completed(futures):
                    ip = futures[fut]
                    try:
                        info_map[ip] = fut.result()
                    except Exception:
                        info_map[ip] = GeoInfo()
                    if on_progress:
                        on_progress(len(info_map), total)

        # 把结果回写到 Node
        for n in node_list:
            if n.ip in info_map:
                n.geo = info_map[n.ip]


__all__ = ["GeoConfig", "GeoEnricher", "_classify_by_text"]
