"""Extended smoke tests — firewall / takeover / CLI 纯逻辑测试.

不含真实 iptables/OpenVPN 调用 (monkeypatch).
"""
from __future__ import annotations

import io
import os
import socket
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

from orionvm.firewall import VpnEndpoint, _require_root_or_sudo
from orionvm.takeover import inject_outbound_mode, tcp_alive
from orionvm.cli import build_parser, main as cli_main


# ===== firewall =====

class FirewallPlatformTest(unittest.TestCase):
    def test_non_linux_raises_in_apply(self) -> None:
        ep = VpnEndpoint(server_ip="1.2.3.4")
        with patch("orionvm.firewall.platform.system", return_value="Windows"):
            with self.assertRaises(RuntimeError):
                from orionvm.firewall import apply_lock
                apply_lock(ep)

    def test_require_root_non_linux(self) -> None:
        with patch("orionvm.firewall.platform.system", return_value="Windows"):
            with self.assertRaises(RuntimeError):
                _require_root_or_sudo()


# ===== takeover =====

class InjectOutboundModeTest(unittest.TestCase):
    def test_inject_out_keeps_local_only(self) -> None:
        raw = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\n"
        out = inject_outbound_mode(raw, "out")
        self.assertIn("redirect-gateway local def1", out)
        self.assertNotIn("bypass-dhcp", out)
        self.assertNotIn("block-outside-dns", out)

    def test_inject_full_adds_def1_bypass(self) -> None:
        raw = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\n"
        out = inject_outbound_mode(raw, "full")
        self.assertIn("redirect-gateway def1 bypass-dhcp", out)
        self.assertIn("block-outside-dns", out)

    def test_removes_pushed_redirect(self) -> None:
        raw = 'push "redirect-gateway def1"\npush "dhcp-option DNS 8.8.8.8"\n'
        out = inject_outbound_mode(raw, "full")
        self.assertNotIn('push "redirect-gateway', out)
        self.assertIn("redirect-gateway def1 bypass-dhcp", out)

    def test_output_is_string_and_non_empty(self) -> None:
        raw = "client\ndev tun\n"
        out = inject_outbound_mode(raw, "out")
        self.assertIsInstance(out, str)
        self.assertTrue(out.strip())


class TcpAliveTest(unittest.TestCase):
    def test_refuses_closed_port(self) -> None:
        self.assertFalse(tcp_alive("github.com", 65535, timeout=1.0))

    def test_accepts_local_port(self) -> None:
        with _socket_context() as srv:
            self.assertTrue(tcp_alive("127.0.0.1", srv["port"], timeout=2.0))

    def test_invalid_host_returns_false(self) -> None:
        self.assertFalse(tcp_alive("255.255.255.255", 1, timeout=0.5))


@contextmanager
def _socket_context():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        yield {"port": port, "sock": srv}
    finally:
        srv.close()


# ===== CLI =====

class CLITest(unittest.TestCase):
    def _parse(self, *argv: str):
        return build_parser().parse_args(argv)

    def _main(self, *argv: str) -> int:
        return cli_main(list(argv))

    def test_default_is_scan(self) -> None:
        # With no argv, CLI defaults to the 'scan' subcommand.
        # It may return 0 or 1 depending on network availability in the test env.
        rc = self._main()
        self.assertIn(rc, (0, 1))

    def test_scan_subcommand(self) -> None:
        args = self._parse("scan")
        self.assertEqual(args.command, "scan")

    def test_stop_subcommand(self) -> None:
        args = self._parse("stop")
        self.assertEqual(args.command, "stop")

    def test_log_follow_flag(self) -> None:
        args = self._parse("log", "-f")
        self.assertTrue(args.follow)

    def _parse_start(self, *extra: str):
        return build_parser().parse_args(["start", *extra])

    def test_start_accepts_ovpn(self) -> None:
        args = self._parse_start("--ovpn", "/tmp/x.ovpn")
        self.assertEqual(args.command, "start")
        self.assertEqual(args.ovpn, "/tmp/x.ovpn")

    def test_mode_out(self) -> None:
        args = self._parse("--out")
        self.assertEqual(args.mode, "out")

    def test_mode_full(self) -> None:
        args = self._parse("--full")
        self.assertEqual(args.mode, "full")


if __name__ == "__main__":
    unittest.main()
