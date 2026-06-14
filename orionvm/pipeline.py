"""OrionVM pipeline — 串联 fetcher → probe → geo → sort."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .fetcher import FetcherConfig, VPNGateFetcher
from .geo import GeoConfig, GeoEnricher
from .models import Node
from .probe import ProbeConfig, ProbeReport, NodeProbe
from .scorer import sort_nodes
from .utils import Logger, write_json


@dataclass(slots=True)
class PipelineConfig:
    max_rows: int = 100
    probe_workers: int = 16
    geo_workers: int = 4
    geo_after_probe: bool = True  # 只对通过 TCP 探测的节点做 IP 质量查询
    run_geo: bool = True  # 是否启用 IP 质量 (被 --no-geo 关掉)
    output_path: Path | None = None


class Pipeline:
    """fetch → probe → [geo] → sort 的总编排."""

    def __init__(
        self,
        config: PipelineConfig | None = None,
        logger: Logger | None = None,
    ) -> None:
        self.config = config or PipelineConfig()
        self.log = logger or Logger()

    def run(self) -> list[Node]:
        # ---- 1. 拉取 ----
        self.log.info(f"fetching nodes (max_rows={self.config.max_rows})...")
        try:
            nodes = VPNGateFetcher(FetcherConfig(max_rows=self.config.max_rows)).fetch()
        except Exception as e:
            self.log.error(f"fetch failed: {e}")
            return []
        self.log.info(f"fetched {len(nodes)} raw nodes")

        # ---- 2. 探测连通性 ----
        def on_probe(done: int, total: int, rpt: ProbeReport) -> None:
            tag = "ok " if rpt.passed else "fail"
            lat = rpt.result.latency_ms
            self.log.info(f"[{done}/{total}] {tag}  {rpt.node.ip:<16} {rpt.node.country_code:<3} {lat}ms")

        probe = NodeProbe(ProbeConfig(workers=self.config.probe_workers))
        reports = probe.probe_many(nodes, on_progress=on_probe)
        alive_nodes = [r.node for r in reports if r.passed]
        self.log.info(f"alive after probe: {len(alive_nodes)}/{len(nodes)}")

        # ---- 3. IP 质量 ----
        if not self.config.run_geo:
            self.log.info("geo step skipped (run_geo=False)")
        else:
            if self.config.geo_after_probe:
                target = alive_nodes
            else:
                target = nodes
            if target:
                self.log.info(f"enriching geo for {len(target)} nodes...")

                def on_geo(done: int, total: int) -> None:
                    self.log.info(f"  geo [{done}/{total}]")

                try:
                    GeoEnricher(GeoConfig(workers=self.config.geo_workers)).enrich(
                        target, on_progress=on_geo,
                    )
                except Exception as e:
                    self.log.error(f"geo enrich failed (skipping): {e}")

        # ---- 4. 排序 ----
        ranked_all = sort_nodes(nodes)
        self.log.info(
            f"top 5: "
            + ", ".join(
                f"{n.ip}({n.probe.latency_ms}ms,{n.geo.ip_type})"
                for n in ranked_all[:5]
            )
        )

        # ---- 5. 输出 ----
        if self.config.output_path:
            write_json(self.config.output_path, [n.to_dict() for n in ranked_all])
            self.log.info(f"saved {len(ranked_all)} nodes -> {self.config.output_path}")

        return ranked_all


__all__ = ["PipelineConfig", "Pipeline"]
