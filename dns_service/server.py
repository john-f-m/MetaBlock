#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import logging
import socket
import socketserver
from pathlib import Path
from typing import Iterable

try:
    from dnslib import DNSRecord, QTYPE, RCODE
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing dependency: dnslib. Install with `pip install -r requirements.txt`."
    ) from exc


def read_non_comment_lines(path: Path, lowercase: bool = False) -> list[str]:
    values: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        values.append(line.lower() if lowercase else line)
    return values


def parse_upstream(value: str) -> tuple[str, int]:
    text = value.strip()
    if text.startswith("["):
        if "]" not in text:
            raise ValueError(f"Invalid upstream: {value}")
        host, rest = text[1:].split("]", 1)
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, 53

    if text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        return host, int(port)

    if text.count(":") > 1:
        return text, 53

    return text, 53


class BlockPolicy:
    def __init__(self, blocked_domains: Iterable[str], blocked_prefixes: Iterable[str]) -> None:
        self.blocked_domains = tuple(sorted({d.strip(".").lower() for d in blocked_domains if d}))
        v4: list[ipaddress.IPv4Network] = []
        v6: list[ipaddress.IPv6Network] = []
        for prefix in blocked_prefixes:
            network = ipaddress.ip_network(prefix, strict=False)
            if network.version == 4:
                v4.append(network)
            else:
                v6.append(network)
        self.v4_prefixes = tuple(v4)
        self.v6_prefixes = tuple(v6)

    def is_blocked_domain(self, qname: str) -> bool:
        name = qname.strip(".").lower()
        for domain in self.blocked_domains:
            if name == domain or name.endswith(f".{domain}"):
                return True
        return False

    def contains_blocked_ip(self, dns_response: DNSRecord) -> bool:
        for rr in dns_response.rr:
            rr_type = QTYPE[rr.rtype]
            if rr_type not in ("A", "AAAA"):
                continue
            try:
                ip = ipaddress.ip_address(str(rr.rdata))
            except ValueError:
                continue

            prefixes = self.v4_prefixes if ip.version == 4 else self.v6_prefixes
            for prefix in prefixes:
                if ip in prefix:
                    return True
        return False


class DNSResolver:
    def __init__(
        self,
        policy: BlockPolicy,
        upstream_host: str,
        upstream_port: int,
        timeout: float,
    ) -> None:
        self.policy = policy
        self.timeout = timeout
        self.upstream = self._resolve_upstream(upstream_host, upstream_port)

    @staticmethod
    def _resolve_upstream(host: str, port: int) -> tuple[socket.AddressFamily, tuple]:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        family, _, _, _, sockaddr = infos[0]
        return family, sockaddr

    def resolve(self, query_data: bytes) -> bytes:
        try:
            query = DNSRecord.parse(query_data)
        except Exception:
            return b""

        qname = str(query.q.qname).rstrip(".").lower()
        qtype = QTYPE[query.q.qtype]

        if self.policy.is_blocked_domain(qname):
            logging.info("Blocked domain query: %s (%s)", qname, qtype)
            return self._build_reply(query, RCODE.NXDOMAIN)

        upstream_response = self._forward(query_data)
        if upstream_response is None:
            logging.warning("Upstream timeout/failure for %s", qname)
            return self._build_reply(query, RCODE.SERVFAIL)

        try:
            parsed_response = DNSRecord.parse(upstream_response)
        except Exception:
            return upstream_response

        if self.policy.contains_blocked_ip(parsed_response):
            logging.info("Blocked response IP for %s (%s)", qname, qtype)
            return self._build_reply(query, RCODE.NXDOMAIN)

        return upstream_response

    def _forward(self, query_data: bytes) -> bytes | None:
        family, sockaddr = self.upstream
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            try:
                sock.sendto(query_data, sockaddr)
                response, _ = sock.recvfrom(65535)
                return response
            except OSError:
                return None

    @staticmethod
    def _build_reply(query: DNSRecord, rcode: int) -> bytes:
        reply = query.reply()
        reply.header.rcode = rcode
        reply.rr.clear()
        reply.auth.clear()
        reply.ar.clear()
        return reply.pack()


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], handler, resolver: DNSResolver):
        super().__init__(server_address, handler)
        self.resolver = resolver


class DNSUDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        response = self.server.resolver.resolve(data)
        if response:
            sock.sendto(response, self.client_address)


def main() -> int:
    root = Path(__file__).resolve().parents[1]

    parser = argparse.ArgumentParser(
        description="DNS forwarder that blocks Meta domains and ASN IP ranges."
    )
    parser.add_argument("--listen", default="0.0.0.0", help="Listen address")
    parser.add_argument("--port", type=int, default=5353, help="Listen port")
    parser.add_argument(
        "--upstream",
        default="1.1.1.1:53",
        help="Upstream resolver as host:port (IPv6 supported).",
    )
    parser.add_argument(
        "--domain-list",
        type=Path,
        default=root / "generated" / "meta_domains.txt",
        help="Generated domain blocklist file.",
    )
    parser.add_argument(
        "--prefix-list",
        type=Path,
        default=root / "generated" / "meta_prefixes.txt",
        help="Generated prefix blocklist file.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Upstream timeout in seconds.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not args.domain_list.exists():
        logging.error("Missing domain list: %s", args.domain_list)
        return 1
    if not args.prefix_list.exists():
        logging.error("Missing prefix list: %s", args.prefix_list)
        return 1

    blocked_domains = read_non_comment_lines(args.domain_list, lowercase=True)
    blocked_prefixes = read_non_comment_lines(args.prefix_list, lowercase=False)

    upstream_host, upstream_port = parse_upstream(args.upstream)
    policy = BlockPolicy(blocked_domains, blocked_prefixes)
    resolver = DNSResolver(policy, upstream_host, upstream_port, args.timeout)

    with ThreadingUDPServer((args.listen, args.port), DNSUDPHandler, resolver) as server:
        logging.info(
            "MetaBlock DNS listening on %s:%s (domains=%d, prefixes=%d, upstream=%s:%d)",
            args.listen,
            args.port,
            len(policy.blocked_domains),
            len(policy.v4_prefixes) + len(policy.v6_prefixes),
            upstream_host,
            upstream_port,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logging.info("Shutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
