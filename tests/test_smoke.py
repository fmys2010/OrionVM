"""Smoke tests — 不发网络包, 只验证 models/utils/scorer 的纯逻辑."""
from __future__ import annotations

import unittest

from orionvm.models import GeoInfo, Node, ProbeResult
from orionvm.scorer import score_node, sort_nodes, latency_to_score
from orionvm.utils import parse_openvpn_remote, safe_int


class UtilsTest(unittest.TestCase):
    def test_safe_int(self) -> None:
        self.assertEqual(safe_int("12"), 12)
        self.assertEqual(safe_int(None), 0)
        self.assertEqual(safe_int("xx", 7), 7)

    def test_parse_openvpn_remote(self) -> None:
        cfg = "\n# comment\nremote vpn.example.com 1194 udp\nproto udp\n    "
        h, p, proto = parse_openvpn_remote(cfg)
        self.assertEqual(h, "vpn.example.com")
        self.assertEqual(p, 1194)
        self.assertEqual(proto, "udp")


class ScorerTest(unittest.TestCase):
    def test_latency_to_score_monotone(self) -> None:
        self.assertGreater(latency_to_score(50), latency_to_score(200))
        self.assertGreater(latency_to_score(200), latency_to_score(800))
        self.assertGreaterEqual(latency_to_score(1500), 0.0)
        self.assertLess(latency_to_score(1500), 0.05)

    def test_score_node_weights(self) -> None:
        n = Node(
            id="JP_1.2.3.4_443_tcp",
            ip="1.2.3.4",
            country_code="JP",
            remote_host="1.2.3.4",
            remote_port=443,
            protocol="tcp",
            speed_bps=100_000_000,
            geo=GeoInfo(ip_type="residential", trust_score=90),
            probe=ProbeResult(alive=True, latency_ms=80),
        )
        b = score_node(n)
        self.assertTrue(b.reachable)
        self.assertGreaterEqual(b.score, 50.0)
        self.assertLessEqual(b.score, 100.0)

    def test_sort_orders_correctly(self) -> None:
        n_good = Node(
            id="JP_1.1.1.1_443_tcp",
            ip="1.1.1.1",
            country_code="JP",
            probe=ProbeResult(alive=True, latency_ms=50),
            geo=GeoInfo(ip_type="residential", trust_score=90),
        )
        n_bad = Node(
            id="US_2.2.2.2_443_tcp",
            ip="2.2.2.2",
            country_code="US",
            probe=ProbeResult(alive=False, error="tcp_unreachable"),
            geo=GeoInfo(ip_type="datacenter", trust_score=30),
        )
        n_decent = Node(
            id="KR_3.3.3.3_443_tcp",
            ip="3.3.3.3",
            country_code="KR",
            probe=ProbeResult(alive=True, latency_ms=300),
            geo=GeoInfo(ip_type="mobile", trust_score=75),
        )
        ranked = sort_nodes([n_bad, n_decent, n_good])
        self.assertIs(ranked[0], n_good)
        self.assertIs(ranked[-1], n_bad)


if __name__ == "__main__":
    unittest.main()
