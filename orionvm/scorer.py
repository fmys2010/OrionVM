"""OrionVM 节点评分与排序."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable

from .models import Node


@dataclass(slots=True)
class ScoreBreakdown:
    score: float
    reachable: bool
    latency: int
    type_factor: float
    trust_factor: float
    api_speed_factor: float


# 评分采用 0-100 加权和
WEIGHTS = {
    "reachable": 30.0,
    "latency": 30.0,
    "type": 15.0,
    "trust": 15.0,
    "api_speed": 10.0,
}

# IP 类型 → factor (1.0 最优)
TYPE_FACTOR = {
    "residential": 1.00,
    "mobile": 0.90,
    "unknown": 0.65,
    "hosting": 0.40,
    "datacenter": 0.30,
    "proxy": 0.10,
}


def latency_to_score(ms: int) -> float:
    """延迟 → 0-1, 用 sigmoid 包络, 50ms 满分, 800ms 趋向 0."""
    if ms <= 0:
        return 0.0
    # 用 logistic: 1 / (1 + exp((ms-200)/120))
    z = (ms - 200.0) / 120.0
    return 1.0 / (1.0 + math.exp(z))


def api_speed_to_score(bps: int) -> float:
    """API 自报带宽 → 0-1, 100Mbps 满分."""
    if bps <= 0:
        return 0.5
    # log scale
    return min(1.0, math.log10(bps / 1_000_000 + 1) / math.log10(101))


def score_node(node: Node) -> ScoreBreakdown:
    reachable = node.probe.alive and node.probe.latency_ms > 0 and not node.probe.error
    lat_score = latency_to_score(node.probe.latency_ms)
    type_factor = TYPE_FACTOR.get(node.geo.ip_type, 0.50)
    trust = max(0.0, min(1.0, node.geo.trust_score / 100.0))
    api_speed = api_speed_to_score(node.speed_bps)

    parts = [
        WEIGHTS["reachable"] * (1.0 if reachable else 0.0),
        WEIGHTS["latency"] * (lat_score if reachable else 0.0),
        WEIGHTS["type"] * type_factor,
        WEIGHTS["trust"] * trust,
        WEIGHTS["api_speed"] * api_speed,
    ]
    total = sum(parts)
    return ScoreBreakdown(
        score=round(total, 2),
        reachable=reachable,
        latency=node.probe.latency_ms,
        type_factor=type_factor,
        trust_factor=trust,
        api_speed_factor=api_speed,
    )


def sort_nodes(nodes: Iterable[Node]) -> list[Node]:
    """主排序: 分数降序, 同分按延迟升序, 再按 trust_score 降序."""

    def key(n: Node) -> tuple:
        b = score_node(n)
        return (
            -b.score,
            n.probe.latency_ms if b.reachable else 10**9,
            -n.geo.trust_score,
            -n.speed_bps,
        )

    return sorted(nodes, key=key)


__all__ = ["ScoreBreakdown", "score_node", "sort_nodes", "WEIGHTS", "TYPE_FACTOR"]
