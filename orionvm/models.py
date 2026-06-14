"""OrionVM 数据模型."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class GeoInfo:
    """IP 地理与质量元信息 (来自外部 API 拼装)."""

    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    ip_type: str = "unknown"  # residential / mobile / hosting / proxy / datacenter / unknown
    is_flagged: bool = False
    trust_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GeoInfo":
        return cls(
            country=d.get("country", ""),
            country_code=d.get("country_code", ""),
            region=d.get("region", ""),
            city=d.get("city", ""),
            isp=d.get("isp", ""),
            org=d.get("org", ""),
            asn=d.get("asn", ""),
            ip_type=d.get("ip_type", "unknown"),
            is_flagged=bool(d.get("is_flagged", False)),
            trust_score=int(d.get("trust_score", 0) or 0),
        )


@dataclass(slots=True)
class ProbeResult:
    """单个节点探测结果."""

    alive: bool = False
    latency_ms: int = 0
    jitter_ms: int = 0
    loss_pct: float = 0.0
    tcp_rtt_ms: int = 0
    icmp_rtt_ms: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ProbeResult":
        return cls(
            alive=bool(d.get("alive", False)),
            latency_ms=int(d.get("latency_ms", 0) or 0),
            jitter_ms=int(d.get("jitter_ms", 0) or 0),
            loss_pct=float(d.get("loss_pct", 0.0) or 0.0),
            tcp_rtt_ms=int(d.get("tcp_rtt_ms", 0) or 0),
            icmp_rtt_ms=int(d.get("icmp_rtt_ms", 0) or 0),
            error=str(d.get("error", "")),
        )


@dataclass(slots=True)
class Node:
    """统一节点结构."""

    id: str
    ip: str
    hostname: str = ""
    country: str = ""
    country_code: str = ""
    operator: str = ""
    score: int = 0
    speed_bps: int = 0  # VPNGate API 报告值 (未必可信)
    sessions: int = 0
    uptime_days: int = 0
    log_type: str = ""
    operator_msg: str = ""
    remote_host: str = ""
    remote_port: int = 0
    protocol: str = "tcp"
    openvpn_config_b64: str = ""

    geo: GeoInfo = field(default_factory=GeoInfo)
    probe: ProbeResult = field(default_factory=ProbeResult)

    fetched_at: float = 0.0
    probed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Node":
        geo_raw = d.get("geo") or {}
        probe_raw = d.get("probe") or {}
        kwargs = {k: v for k, v in d.items() if k not in ("geo", "probe")}
        return cls(
            geo=GeoInfo.from_dict(geo_raw) if isinstance(geo_raw, dict) else GeoInfo(),
            probe=ProbeResult.from_dict(probe_raw) if isinstance(probe_raw, dict) else ProbeResult(),
            **kwargs,
        )
