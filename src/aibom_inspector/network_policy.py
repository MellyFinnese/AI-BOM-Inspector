from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse


class NetworkPolicyViolation(PermissionError):
    pass


@dataclass(frozen=True)
class NetworkPolicy:
    allowed_ingress_cidrs: tuple[str, ...] = ()
    denied_ingress_cidrs: tuple[str, ...] = ()
    allowed_egress_hosts: tuple[str, ...] = ()
    denied_egress_hosts: tuple[str, ...] = ()
    allowed_egress_ports: tuple[int, ...] = (443,)
    deny_private_destinations: bool = True

    def _networks(self, values: tuple[str, ...]) -> tuple[ipaddress._BaseNetwork, ...]:
        return tuple(ipaddress.ip_network(value, strict=False) for value in values)

    def authorize_ingress(self, source_ip: str) -> None:
        source = ipaddress.ip_address(source_ip)
        if any(source in network for network in self._networks(self.denied_ingress_cidrs)):
            raise NetworkPolicyViolation(f"ingress denied for {source_ip}")
        allowed = self._networks(self.allowed_ingress_cidrs)
        if allowed and not any(source in network for network in allowed):
            raise NetworkPolicyViolation(f"ingress not allowlisted for {source_ip}")

    def authorize_egress(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise NetworkPolicyViolation("only HTTP(S) egress URLs are permitted")
        host = parsed.hostname.lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if self.allowed_egress_ports and port not in self.allowed_egress_ports:
            raise NetworkPolicyViolation(f"egress port {port} is not allowed")
        if host in {item.lower().rstrip(".") for item in self.denied_egress_hosts}:
            raise NetworkPolicyViolation(f"egress host {host} is denied")
        allowed_hosts = {item.lower().rstrip(".") for item in self.allowed_egress_hosts}
        if allowed_hosts and host not in allowed_hosts:
            raise NetworkPolicyViolation(f"egress host {host} is not allowlisted")
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
        except socket.gaierror as exc:
            raise NetworkPolicyViolation(f"unable to resolve egress host {host}") from exc
        for value in addresses:
            address = ipaddress.ip_address(value)
            if self.deny_private_destinations and (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved):
                raise NetworkPolicyViolation(f"private/link-local egress destination denied: {value}")
        return host
