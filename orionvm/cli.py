"""OrionVM 命令行入口."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .pipeline import Pipeline, PipelineConfig
from .scorer import score_node, sort_nodes
from .utils import configure_stdio, Logger


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="orionvm",
        description="OrionVM — VPNGate 节点获取 + 质量测试",
    )
    p.add_argument("--max-scan", type=int, default=80, metavar="N",
                   help="从 VPNGate API 拉的最多节点行数 (默认 80)")
    p.add_argument("--workers", type=int, default=16, metavar="N",
                   help="TCP probe 并发数 (默认 16)")
    p.add_argument("--output", type=Path, default=None,
                   help="输出 JSON 路径, 默认 data/nodes.json")
    p.add_argument("--no-geo", action="store_true",
                   help="跳过 IP 质量查询 (residential/mobile/...)")
    p.add_argument("--no-probe-geo", action="store_true",
                   help="不只探测通过的节点才查 geo (默认只查 alive)")
    p.add_argument("--top", type=int, default=10, metavar="N",
                   help="打印排名前 N (默认 10)")
    p.add_argument("--version", action="version", version=f"orionvm {__version__}")
    return p


def _print_ranked(nodes, top: int, log: Logger) -> None:
    ranked = sort_nodes(nodes)[:top]
    rows = []
    headers = ("#", "score", "ip", "cc", "lat_ms", "type", "trust", "spd_mbps", "alive")
    for i, n in enumerate(ranked, 1):
        b = score_node(n)
        mbps = (n.speed_bps or 0) / 1_000_000
        rows.append((
            f"{i}",
            f"{b.score:5.1f}",
            n.ip,
            n.country_code or "??",
            f"{n.probe.latency_ms:>4d}",
            n.geo.ip_type[:9],
            f"{n.geo.trust_score:>3d}",
            f"{mbps:7.1f}",
            "yes" if b.reachable else "NO ",
        ))

    widths = [max(len(str(r[i])) for r in [headers, *rows]) for i in range(len(headers))]
    fmt = "  ".join("{:<%d}" % w for w in widths)
    log.info(fmt.format(*headers))
    log.info("-" * (sum(widths) + 2 * (len(headers) - 1)))
    for r in rows:
        log.info(fmt.format(*r))


def main(argv: list[str] | None = None) -> int:
    configure_stdio()
    parser = _build_parser()
    args = parser.parse_args(argv)
    log = Logger()
    log.info(f"orionvm v{__version__}")

    output = args.output or Path("data/nodes.json")
    output.parent.mkdir(parents=True, exist_ok=True)

    cfg = PipelineConfig(
        max_rows=args.max_scan,
        probe_workers=args.workers,
        geo_after_probe=not args.no_probe_geo,
        run_geo=not args.no_geo,
        output_path=output,
    )
    pipe = Pipeline(cfg, log)
    nodes = pipe.run()
    if not nodes:
        log.error("no nodes returned")
        return 2

    # 写盘 (pipeline.run 也会写, 这里保留双写保险)
    output.write_text(
        json.dumps([n.to_dict() for n in nodes], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    log.info(f"saved -> {output}")

    _print_ranked(nodes, args.top, log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
