#!/usr/bin/env python3
"""Runtime for the Home Assistant WireGuard Client Router app.

The module deliberately uses only Python's standard library. All network state
is created inside the app's own network namespace and is removed on shutdown.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit


APP_NAME = "WireGuard Client Router"
INTERFACE = "wg0"
LAN_INTERFACE = "eth0"
NFT_FAMILY = "inet"
NFT_TABLE = "ha_wg_client"
OPTIONS_PATH = Path(os.environ.get("OPTIONS_PATH", "/data/options.json"))
CONFIG_DIR = Path(os.environ.get("CONFIG_DIR", "/config"))
RUN_DIR = Path(os.environ.get("RUN_DIR", "/run/wireguard-client-router"))
PRIVATE_KEY_PATH = CONFIG_DIR / "private.key"
PUBLIC_KEY_PATH = CONFIG_DIR / "public.key"
RUNTIME_PRIVATE_KEY_PATH = RUN_DIR / "private.key"
RUNTIME_PRESHARED_KEY_PATH = RUN_DIR / "preshared.key"
IMPORTED_CONFIG_PATH = CONFIG_DIR / "imported_config.json"
WEB_ROOT = Path(__file__).resolve().parent / "web"
INGRESS_HOST = os.environ.get("INGRESS_HOST", "0.0.0.0")
INGRESS_PORT = int(os.environ.get("INGRESS_PORT", "8099"))
MAX_REQUEST_BYTES = 128 * 1024
MAX_WIREGUARD_CONFIG_BYTES = 64 * 1024
INGRESS_PROXY_ADDRESS = "172.30.32.2"

RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
TUNNEL_IPV4_NETWORKS = (
    *RFC1918_NETWORKS,
    ipaddress.ip_network("100.64.0.0/10"),
)
HOME_ASSISTANT_INTERNAL_NETWORKS = (
    ipaddress.ip_network("172.30.32.0/23"),
)

ENDPOINT_RE = re.compile(
    r"^(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?):(?P<port>[0-9]{1,5})$"
)


class ConfigError(ValueError):
    """Raised for a safe, user-actionable configuration error."""


class CommandError(RuntimeError):
    """Raised when a networking command fails."""


@dataclass(frozen=True)
class Settings:
    endpoint: str
    endpoint_host: str
    endpoint_port: int
    server_public_key: str
    preshared_key: str | None
    client_address: ipaddress.IPv4Interface
    private_key: str | None
    generate_private_key: bool
    remote_subnets: tuple[ipaddress.IPv4Network, ...]
    lan_targets: tuple[ipaddress.IPv4Network, ...]
    persistent_keepalive: int
    mtu: int
    log_level: str

    @property
    def secrets(self) -> tuple[str, ...]:
        return tuple(
            value
            for value in (
                self.server_public_key,
                self.private_key,
                self.preshared_key,
            )
            if value
        )


@dataclass(frozen=True)
class ImportedWireGuardConfig:
    endpoint: str
    server_public_key: str
    preshared_key: str | None
    client_address: str
    private_key: str
    mtu: int
    persistent_keepalive: int
    allowed_ips: tuple[str, ...]
    suggested_remote_subnets: tuple[str, ...]
    suggested_lan_targets: tuple[str, ...]
    warnings: tuple[str, ...]

    def preview(self) -> dict[str, Any]:
        fingerprint = hashlib.sha256(
            base64.b64decode(self.server_public_key)
        ).hexdigest()[:12]
        return {
            "endpoint": self.endpoint,
            "client_address": self.client_address,
            "mtu": self.mtu,
            "persistent_keepalive": self.persistent_keepalive,
            "allowed_ips": list(self.allowed_ips),
            "suggested_remote_subnets": list(self.suggested_remote_subnets),
            "suggested_lan_targets": list(self.suggested_lan_targets),
            "has_private_key": True,
            "has_preshared_key": self.preshared_key is not None,
            "server_key_fingerprint": fingerprint,
            "warnings": list(self.warnings),
        }


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be an object")
    return value


def _parse_endpoint(value: Any) -> tuple[str, str, int]:
    if not isinstance(value, str) or not value:
        raise ConfigError("server.endpoint is required")
    match = ENDPOINT_RE.fullmatch(value)
    if not match:
        raise ConfigError(
            "server.endpoint must use host:port or [IPv6-address]:port syntax"
        )
    port = int(match.group("port"))
    if not 1 <= port <= 65535:
        raise ConfigError("server.endpoint port must be between 1 and 65535")
    host = match.group("host")
    if host.startswith("["):
        host = host[1:-1]
        try:
            ipaddress.IPv6Address(host)
        except ValueError as err:
            raise ConfigError("server.endpoint contains an invalid IPv6 address") from err
    return value, host, port


def _validate_wg_key(value: Any, label: str, *, optional: bool = False) -> str | None:
    if optional and (value is None or value == ""):
        return None
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{label} is required")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as err:
        raise ConfigError(f"{label} must be a valid WireGuard base64 key") from err
    if len(raw) != 32:
        raise ConfigError(f"{label} must decode to exactly 32 bytes")
    return value


def _parse_client_address(value: Any) -> ipaddress.IPv4Interface:
    if not isinstance(value, str):
        raise ConfigError("client.address must be an IPv4 interface address")
    try:
        address = ipaddress.ip_interface(value)
    except ValueError as err:
        raise ConfigError("client.address must be a valid IPv4 CIDR") from err
    if not isinstance(address, ipaddress.IPv4Interface):
        raise ConfigError("IPv6 is not supported in this release")
    if address.network.prefixlen != 32:
        raise ConfigError("client.address must use a /32 prefix")
    if address.ip.is_unspecified or address.ip.is_multicast or address.ip.is_loopback:
        raise ConfigError("client.address is not usable for a WireGuard peer")
    if not any(address.ip in network for network in TUNNEL_IPV4_NETWORKS):
        raise ConfigError(
            "client.address must use RFC1918 private or RFC6598 shared address space"
        )
    return address


def _parse_networks(value: Any, label: str) -> tuple[ipaddress.IPv4Network, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{label} must contain at least one IPv4 CIDR")
    if len(value) > 64:
        raise ConfigError(f"{label} may contain at most 64 entries")
    networks: list[ipaddress.IPv4Network] = []
    for item in value:
        if not isinstance(item, str):
            raise ConfigError(f"{label} entries must be IPv4 CIDR strings")
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as err:
            raise ConfigError(f"{label} contains an invalid or non-canonical CIDR") from err
        if not isinstance(network, ipaddress.IPv4Network):
            raise ConfigError("IPv6 is not supported in this release")
        if network.prefixlen == 0:
            raise ConfigError(f"{label} must not contain 0.0.0.0/0")
        if network.is_multicast or network.is_loopback or network.is_unspecified:
            raise ConfigError(f"{label} contains an unusable network")
        networks.append(network)
    return tuple(sorted(set(networks), key=lambda item: (int(item.network_address), item.prefixlen)))


def _overlap(
    left: Iterable[ipaddress.IPv4Network], right: Iterable[ipaddress.IPv4Network]
) -> tuple[ipaddress.IPv4Network, ipaddress.IPv4Network] | None:
    for first in left:
        for second in right:
            if first.overlaps(second):
                return first, second
    return None


def _strip_inline_comment(value: str) -> str:
    for marker in (" #", " ;"):
        value = value.split(marker, 1)[0]
    return value.strip()


def parse_wireguard_config(config_text: Any) -> ImportedWireGuardConfig:
    if not isinstance(config_text, str) or not config_text.strip():
        raise ConfigError("Die WireGuard-Konfiguration ist leer")
    if len(config_text.encode("utf-8")) > MAX_WIREGUARD_CONFIG_BYTES:
        raise ConfigError("Die WireGuard-Konfiguration ist größer als 64 KiB")

    sections: list[tuple[str, dict[str, str]]] = []
    current_name: str | None = None
    current_values: dict[str, str] | None = None
    forbidden_directives = {"preup", "postup", "predown", "postdown"}

    for line_number, raw_line in enumerate(config_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_name = line[1:-1].strip().lower()
            if current_name not in {"interface", "peer"}:
                raise ConfigError(
                    f"Nicht unterstützter Abschnitt in Zeile {line_number}: {line}"
                )
            current_values = {}
            sections.append((current_name, current_values))
            continue
        if current_values is None or current_name is None:
            raise ConfigError(
                f"Eintrag außerhalb eines Abschnitts in Zeile {line_number}"
            )
        if "=" not in line:
            raise ConfigError(f"Ungültiger Eintrag in Zeile {line_number}")
        raw_key, raw_value = line.split("=", 1)
        key = raw_key.strip().lower()
        value = _strip_inline_comment(raw_value)
        if key in forbidden_directives:
            raise ConfigError(
                "PreUp, PostUp, PreDown und PostDown werden aus Sicherheitsgründen nicht importiert"
            )
        if key in current_values:
            raise ConfigError(
                f"Doppelter Eintrag '{raw_key.strip()}' in Zeile {line_number}"
            )
        current_values[key] = value

    interfaces = [values for name, values in sections if name == "interface"]
    peers = [values for name, values in sections if name == "peer"]
    if len(interfaces) != 1:
        raise ConfigError("Die Konfiguration muss genau einen [Interface]-Abschnitt enthalten")
    if len(peers) != 1:
        raise ConfigError("Die Konfiguration muss genau einen [Peer]-Abschnitt enthalten")

    interface = interfaces[0]
    peer = peers[0]
    warnings: list[str] = []

    private_key = _validate_wg_key(
        interface.get("privatekey"), "Interface.PrivateKey"
    )
    server_public_key = _validate_wg_key(peer.get("publickey"), "Peer.PublicKey")
    preshared_key = _validate_wg_key(
        peer.get("presharedkey"), "Peer.PresharedKey", optional=True
    )
    endpoint, _endpoint_host, _endpoint_port = _parse_endpoint(peer.get("endpoint"))

    address_values = [
        item.strip()
        for item in interface.get("address", "").split(",")
        if item.strip()
    ]
    ipv4_addresses: list[str] = []
    for value in address_values:
        try:
            parsed_address = ipaddress.ip_interface(value)
        except ValueError as err:
            raise ConfigError("Interface.Address enthält eine ungültige Adresse") from err
        if isinstance(parsed_address, ipaddress.IPv4Interface):
            ipv4_addresses.append(str(parsed_address))
        else:
            warnings.append("IPv6-Adresse wurde ignoriert; diese Version unterstützt nur IPv4.")
    if len(ipv4_addresses) != 1:
        raise ConfigError("Interface.Address muss genau eine IPv4-Adresse enthalten")
    client_address = str(_parse_client_address(ipv4_addresses[0]))

    mtu_value = interface.get("mtu", "1420")
    keepalive_value = peer.get("persistentkeepalive", "25")
    try:
        mtu = int(mtu_value)
        keepalive = int(keepalive_value)
    except ValueError as err:
        raise ConfigError("MTU und PersistentKeepalive müssen Ganzzahlen sein") from err
    if not 1280 <= mtu <= 1500:
        raise ConfigError("Interface.MTU muss zwischen 1280 und 1500 liegen")
    if not 0 <= keepalive <= 65535:
        raise ConfigError("Peer.PersistentKeepalive muss zwischen 0 und 65535 liegen")

    allowed_values = [
        item.strip()
        for item in peer.get("allowedips", "").split(",")
        if item.strip()
    ]
    if len(allowed_values) > 128:
        raise ConfigError("Peer.AllowedIPs darf höchstens 128 Netze enthalten")
    allowed_networks: list[ipaddress.IPv4Network] = []
    allowed_for_preview: list[str] = []
    for value in allowed_values:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as err:
            raise ConfigError("Peer.AllowedIPs enthält ein ungültiges Netz") from err
        if isinstance(network, ipaddress.IPv6Network):
            warnings.append("IPv6-AllowedIP wurde ignoriert; diese Version unterstützt nur IPv4.")
            continue
        canonical = str(network)
        if canonical != value:
            warnings.append(f"AllowedIP {value} wurde zu {canonical} normalisiert.")
        allowed_networks.append(network)
        allowed_for_preview.append(canonical)

    client_ip = ipaddress.ip_interface(client_address).ip
    remote_suggestions: list[ipaddress.IPv4Network] = []
    lan_suggestions: list[ipaddress.IPv4Network] = []
    for network in allowed_networks:
        if network.prefixlen == 0:
            warnings.append(
                "0.0.0.0/0 wurde nicht übernommen. Das Add-on leitet keinen gesamten Internetverkehr weiter."
            )
            continue
        if any(network.subnet_of(space) for space in TUNNEL_IPV4_NETWORKS) and client_ip in network:
            remote_suggestions.append(network)
            continue
        if (
            any(network.subnet_of(space) for space in RFC1918_NETWORKS)
            and not _overlap((network,), HOME_ASSISTANT_INTERNAL_NETWORKS)
        ):
            lan_suggestions.append(network)

    if not remote_suggestions or all(item.prefixlen == 32 for item in remote_suggestions):
        derived_remote = ipaddress.ip_network(f"{client_ip}/24", strict=False)
        remote_suggestions = [derived_remote]
        warnings.append(
            f"Das entfernte Tunnelnetz wurde als {derived_remote} aus der Client-Adresse abgeleitet. Bitte prüfen."
        )

    known_interface = {"privatekey", "address", "mtu", "dns", "table", "listenport", "saveconfig"}
    known_peer = {"publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive"}
    ignored = sorted((set(interface) - known_interface) | (set(peer) - known_peer))
    if ignored:
        warnings.append("Nicht verwendete Einträge: " + ", ".join(ignored))
    for optional_name in ("dns", "table", "listenport", "saveconfig"):
        if optional_name in interface:
            warnings.append(f"Interface.{optional_name} wird von diesem Add-on nicht verwendet.")

    return ImportedWireGuardConfig(
        endpoint=endpoint,
        server_public_key=server_public_key or "",
        preshared_key=preshared_key,
        client_address=client_address,
        private_key=private_key or "",
        mtu=mtu,
        persistent_keepalive=keepalive,
        allowed_ips=tuple(dict.fromkeys(allowed_for_preview)),
        suggested_remote_subnets=tuple(
            str(item) for item in sorted(set(remote_suggestions), key=str)
        ),
        suggested_lan_targets=tuple(
            str(item) for item in sorted(set(lan_suggestions), key=str)
        ),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def imported_options(
    imported: ImportedWireGuardConfig,
    remote_subnets: Any,
    lan_targets: Any,
) -> dict[str, Any]:
    options: dict[str, Any] = {
        "server": {
            "endpoint": imported.endpoint,
            "public_key": imported.server_public_key,
        },
        "client": {
            "address": imported.client_address,
            "private_key": imported.private_key,
            "generate_private_key": False,
        },
        "routing": {
            "remote_subnets": remote_subnets,
            "lan_targets": lan_targets,
            "masquerade": True,
        },
        "wireguard": {
            "persistent_keepalive": imported.persistent_keepalive,
            "mtu": imported.mtu,
        },
        "log_level": "info",
    }
    if imported.preshared_key:
        options["server"]["preshared_key"] = imported.preshared_key
    settings_from_options(options)
    return options


def settings_from_options(raw: Any) -> Settings:
    root = _require_mapping(raw, "options")
    server = _require_mapping(root.get("server"), "server")
    client = _require_mapping(root.get("client"), "client")
    routing = _require_mapping(root.get("routing"), "routing")
    wireguard = _require_mapping(root.get("wireguard"), "wireguard")

    endpoint, endpoint_host, endpoint_port = _parse_endpoint(server.get("endpoint"))
    server_public_key = _validate_wg_key(server.get("public_key"), "server.public_key")
    preshared_key = _validate_wg_key(
        server.get("preshared_key"), "server.preshared_key", optional=True
    )
    private_key = _validate_wg_key(
        client.get("private_key"), "client.private_key", optional=True
    )

    generate_private_key = client.get("generate_private_key")
    if not isinstance(generate_private_key, bool):
        raise ConfigError("client.generate_private_key must be true or false")
    if not generate_private_key and not private_key:
        raise ConfigError(
            "client.private_key is required when automatic key generation is disabled"
        )

    client_address = _parse_client_address(client.get("address"))
    remote_subnets = _parse_networks(routing.get("remote_subnets"), "routing.remote_subnets")
    lan_targets = _parse_networks(routing.get("lan_targets"), "routing.lan_targets")

    if routing.get("masquerade") is not True:
        raise ConfigError(
            "routing.masquerade must remain enabled; routed mode is not supported yet"
        )

    for target in lan_targets:
        if not any(target.subnet_of(private) for private in RFC1918_NETWORKS):
            raise ConfigError(
                "routing.lan_targets may contain only RFC1918 private IPv4 networks"
            )
    for source in remote_subnets:
        if not any(source.subnet_of(tunnel) for tunnel in TUNNEL_IPV4_NETWORKS):
            raise ConfigError(
                "routing.remote_subnets may contain only RFC1918 private or RFC6598 shared IPv4 networks"
            )

    internal_overlap = _overlap(
        (*remote_subnets, *lan_targets), HOME_ASSISTANT_INTERNAL_NETWORKS
    )
    if internal_overlap:
        raise ConfigError(
            "Configured networks must not overlap the Home Assistant internal app network"
        )

    routing_overlap = _overlap(remote_subnets, lan_targets)
    if routing_overlap:
        raise ConfigError("remote_subnets and lan_targets must not overlap")

    if any(client_address.ip in target for target in lan_targets):
        raise ConfigError("client.address must not be inside a LAN target")

    keepalive = wireguard.get("persistent_keepalive")
    if not isinstance(keepalive, int) or isinstance(keepalive, bool) or not 0 <= keepalive <= 65535:
        raise ConfigError("wireguard.persistent_keepalive must be between 0 and 65535")
    mtu = wireguard.get("mtu")
    if not isinstance(mtu, int) or isinstance(mtu, bool) or not 1280 <= mtu <= 1500:
        raise ConfigError("wireguard.mtu must be between 1280 and 1500")

    log_level = root.get("log_level", "info")
    if log_level not in {"debug", "info", "warning", "error"}:
        raise ConfigError("log_level must be debug, info, warning, or error")

    return Settings(
        endpoint=endpoint,
        endpoint_host=endpoint_host,
        endpoint_port=endpoint_port,
        server_public_key=server_public_key or "",
        preshared_key=preshared_key,
        client_address=client_address,
        private_key=private_key,
        generate_private_key=generate_private_key,
        remote_subnets=remote_subnets,
        lan_targets=lan_targets,
        persistent_keepalive=keepalive,
        mtu=mtu,
        log_level=log_level,
    )


def _read_options(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as err:
        raise ConfigError(f"Options file does not exist: {path}") from err
    except (OSError, json.JSONDecodeError) as err:
        raise ConfigError("Could not read the Home Assistant options file") from err
    if not isinstance(raw, dict):
        raise ConfigError("Options file must contain a JSON object")
    return raw


def load_settings(path: Path = OPTIONS_PATH) -> Settings:
    return settings_from_options(_read_options(path))


def load_effective_settings(
    options_path: Path = OPTIONS_PATH,
    imported_path: Path = IMPORTED_CONFIG_PATH,
) -> tuple[Settings, str]:
    if imported_path.exists():
        return settings_from_options(_read_options(imported_path)), "import"
    return settings_from_options(_read_options(options_path)), "home_assistant"


def redact(value: str, secrets: Sequence[str]) -> str:
    redacted = value
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


class CommandRunner:
    def __init__(self, secrets: Sequence[str] = ()) -> None:
        self.secrets = tuple(secrets)

    def run(
        self,
        command: Sequence[str],
        *,
        input_text: str | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        logging.debug("Executing networking helper: %s", Path(command[0]).name)
        try:
            result = subprocess.run(
                list(command),
                input=input_text,
                text=True,
                capture_output=True,
                check=False,
            )
        except OSError as err:
            raise CommandError(f"Could not execute {Path(command[0]).name}: {err}") from err
        if check and result.returncode != 0:
            detail = redact(result.stderr.strip() or result.stdout.strip(), self.secrets)
            if len(detail) > 500:
                detail = detail[:500] + "..."
            raise CommandError(
                f"{Path(command[0]).name} failed with exit code {result.returncode}: {detail}"
            )
        return result


def atomic_write(path: Path, value: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, mode)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


class RuntimeStatus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, Any] = {
            "phase": "starting",
            "configured": False,
            "source": None,
            "message": "Das Add-on wird gestartet.",
            "endpoint": None,
            "client_address": None,
            "remote_subnets": [],
            "lan_targets": [],
            "latest_handshake": 0,
            "received_bytes": 0,
            "sent_bytes": 0,
        }

    def update(self, **values: Any) -> None:
        with self._lock:
            self._values.update(values)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            result = dict(self._values)
            result["remote_subnets"] = list(result.get("remote_subnets", []))
            result["lan_targets"] = list(result.get("lan_targets", []))
        handshake = result.get("latest_handshake") or 0
        result["handshake_age_seconds"] = (
            max(0, int(time.time()) - int(handshake)) if handshake else None
        )
        result["public_key"] = None
        try:
            public_key = PUBLIC_KEY_PATH.read_text(encoding="utf-8").strip()
            if _validate_wg_key(public_key, "public key", optional=True):
                result["public_key"] = public_key
        except (OSError, ConfigError):
            pass
        return result


class AppController:
    def __init__(
        self,
        status: RuntimeStatus,
        reload_event: threading.Event,
        imported_path: Path = IMPORTED_CONFIG_PATH,
    ) -> None:
        self.status = status
        self.reload_event = reload_event
        self.imported_path = imported_path
        self._lock = threading.Lock()

    def preview_import(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        imported = parse_wireguard_config(payload.get("config_text"))
        return imported.preview()

    def apply_import(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        imported = parse_wireguard_config(payload.get("config_text"))
        options = imported_options(
            imported,
            payload.get("remote_subnets"),
            payload.get("lan_targets"),
        )
        with self._lock:
            atomic_write(
                self.imported_path,
                json.dumps(options, indent=2, ensure_ascii=False) + "\n",
            )
            self.status.update(
                phase="reloading",
                configured=True,
                source="import",
                message="Die importierte Konfiguration wird aktiviert.",
            )
            self.reload_event.set()
        return {"ok": True, "message": "Konfiguration gespeichert und aktiviert."}

    def reset_import(self) -> dict[str, Any]:
        with self._lock:
            try:
                self.imported_path.unlink()
            except FileNotFoundError:
                pass
            self.status.update(
                phase="reloading",
                message="Die Home-Assistant-Konfiguration wird aktiviert.",
            )
            self.reload_event.set()
        return {"ok": True, "message": "Importierte Konfiguration entfernt."}


class _IngressHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class IngressRequestHandler(BaseHTTPRequestHandler):
    server_version = "WireGuardClientRouter"
    sys_version = ""

    def __init__(
        self,
        *args: Any,
        controller: AppController,
        web_root: Path = WEB_ROOT,
        **kwargs: Any,
    ) -> None:
        self.controller = controller
        self.web_root = web_root
        super().__init__(*args, **kwargs)

    def _is_allowed_client(self) -> bool:
        return (
            os.environ.get("ALLOW_NON_INGRESS") == "1"
            or self.client_address[0] == INGRESS_PROXY_ADDRESS
        )

    def _security_headers(self, *, cache: bool = False) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; connect-src 'self'; "
            "font-src 'self'; frame-ancestors 'self'; img-src 'self' data:; "
            "object-src 'none'; script-src 'self'; style-src 'self'",
        )
        self.send_header(
            "Cache-Control", "public, max-age=3600" if cache else "no-store"
        )

    def _send_bytes(
        self,
        status: HTTPStatus,
        content: bytes,
        content_type: str,
        *,
        cache: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self._security_headers(cache=cache)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(content)

    def _send_json(self, status: HTTPStatus, payload: Mapping[str, Any]) -> None:
        content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, content, "application/json; charset=utf-8")

    def _send_error_json(self, status: HTTPStatus, message: str) -> None:
        self._send_json(status, {"ok": False, "error": message})

    def _read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as err:
            raise ConfigError("Ungültige Anfragegröße") from err
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise ConfigError("Die Anfrage ist leer oder zu groß")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as err:
            raise ConfigError("Die Anfrage enthält kein gültiges JSON") from err
        if not isinstance(payload, dict):
            raise ConfigError("Die Anfrage muss ein JSON-Objekt enthalten")
        return payload

    def _serve_file(self, name: str, content_type: str, *, cache: bool) -> None:
        path = self.web_root / name
        try:
            content = path.read_bytes()
        except OSError:
            self._send_error_json(HTTPStatus.NOT_FOUND, "Datei nicht gefunden")
            return
        self._send_bytes(HTTPStatus.OK, content, content_type, cache=cache)

    def _serve_index(self) -> None:
        try:
            template = (self.web_root / "index.html").read_text(encoding="utf-8")
        except OSError:
            self._send_error_json(HTTPStatus.NOT_FOUND, "Datei nicht gefunden")
            return
        ingress_path = self.headers.get("X-Ingress-Path", "/")
        if not re.fullmatch(r"/[A-Za-z0-9/_-]*", ingress_path):
            ingress_path = "/"
        if not ingress_path.endswith("/"):
            ingress_path += "/"
        content = template.replace("__INGRESS_PATH__", ingress_path).encode("utf-8")
        self._send_bytes(
            HTTPStatus.OK,
            content,
            "text/html; charset=utf-8",
            cache=False,
        )

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        if not self._is_allowed_client():
            self._send_error_json(HTTPStatus.FORBIDDEN, "Zugriff nur über Home Assistant Ingress")
            return
        path = urlsplit(self.path).path
        if path in {"", "/"}:
            self._serve_index()
        elif path == "/static/app.css":
            self._serve_file("app.css", "text/css; charset=utf-8", cache=True)
        elif path == "/static/app.js":
            self._serve_file("app.js", "text/javascript; charset=utf-8", cache=True)
        elif path == "/api/status":
            self._send_json(HTTPStatus.OK, self.controller.status.snapshot())
        else:
            self._send_error_json(HTTPStatus.NOT_FOUND, "Seite nicht gefunden")

    def do_POST(self) -> None:
        if not self._is_allowed_client():
            self._send_error_json(HTTPStatus.FORBIDDEN, "Zugriff nur über Home Assistant Ingress")
            return
        if self.headers.get("X-WG-Request") != "1":
            self._send_error_json(HTTPStatus.FORBIDDEN, "Ungültige Anfrage")
            return
        path = urlsplit(self.path).path
        try:
            payload = self._read_json()
            if path == "/api/import/preview":
                result = self.controller.preview_import(payload)
            elif path == "/api/import/apply":
                result = self.controller.apply_import(payload)
            elif path == "/api/config/reset":
                result = self.controller.reset_import()
            else:
                self._send_error_json(HTTPStatus.NOT_FOUND, "API-Endpunkt nicht gefunden")
                return
        except ConfigError as err:
            self._send_error_json(HTTPStatus.BAD_REQUEST, str(err))
            return
        except OSError:
            logging.exception("Could not persist imported configuration")
            self._send_error_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "Die Konfiguration konnte nicht gespeichert werden.",
            )
            return
        self._send_json(HTTPStatus.OK, result)

    def log_message(self, message_format: str, *args: Any) -> None:
        logging.debug("Ingress request: " + message_format, *args)


class IngressWebServer:
    def __init__(
        self,
        controller: AppController,
        host: str = INGRESS_HOST,
        port: int = INGRESS_PORT,
        web_root: Path = WEB_ROOT,
    ) -> None:
        def handler(*args: Any, **kwargs: Any) -> IngressRequestHandler:
            return IngressRequestHandler(
                *args, controller=controller, web_root=web_root, **kwargs
            )

        self.httpd = _IngressHTTPServer((host, port), handler)
        self.thread = threading.Thread(
            target=self.httpd.serve_forever,
            name="ingress-web-server",
            daemon=True,
        )

    @property
    def port(self) -> int:
        return int(self.httpd.server_address[1])

    def start(self) -> None:
        self.thread.start()
        logging.info("Ingress web interface is listening on port %d", self.port)

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


def build_nft_rules(settings: Settings) -> str:
    remote = ", ".join(str(network) for network in settings.remote_subnets)
    targets = ", ".join(str(network) for network in settings.lan_targets)
    return f"""table {NFT_FAMILY} {NFT_TABLE} {{
  set remote_v4 {{
    type ipv4_addr
    flags interval
    elements = {{ {remote} }}
  }}

  set lan_v4 {{
    type ipv4_addr
    flags interval
    elements = {{ {targets} }}
  }}

  chain forward {{
    type filter hook forward priority filter; policy drop;
    ct state invalid drop
    ct state established,related accept
    iifname \"{INTERFACE}\" oifname \"{LAN_INTERFACE}\" ip saddr @remote_v4 ip daddr @lan_v4 counter accept
  }}

  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname \"{LAN_INTERFACE}\" ip saddr @remote_v4 ip daddr @lan_v4 counter masquerade
  }}
}}
"""


def resolve_endpoint(settings: Settings) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    try:
        results = socket.getaddrinfo(
            settings.endpoint_host,
            settings.endpoint_port,
            type=socket.SOCK_DGRAM,
        )
    except socket.gaierror as err:
        raise CommandError("The WireGuard server endpoint could not be resolved") from err
    addresses = []
    for result in results:
        address = ipaddress.ip_address(result[4][0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise CommandError("The WireGuard server endpoint resolved to no address")
    return tuple(addresses)


def check_endpoint_routes(settings: Settings) -> None:
    for address in resolve_endpoint(settings):
        if isinstance(address, ipaddress.IPv4Address) and any(
            address in network for network in settings.remote_subnets
        ):
            raise ConfigError(
                "server.endpoint resolves inside remote_subnets and would create a routing loop"
            )


class WireGuardRouter:
    def __init__(
        self,
        settings: Settings,
        stop_event: threading.Event,
        reload_event: threading.Event | None = None,
        runtime_status: RuntimeStatus | None = None,
    ) -> None:
        self.settings = settings
        self.stop_event = stop_event
        self.reload_event = reload_event or threading.Event()
        self.runtime_status = runtime_status or RuntimeStatus()
        self.runner = CommandRunner(settings.secrets)
        self.private_key: str | None = None
        self.userspace_process: subprocess.Popen[str] | None = None
        self.last_status_log = 0.0
        self.last_endpoint_refresh = 0.0

    def _read_or_generate_private_key(self) -> str:
        if self.settings.private_key:
            return self.settings.private_key

        if PRIVATE_KEY_PATH.exists():
            stored = PRIVATE_KEY_PATH.read_text(encoding="utf-8").strip()
            validated = _validate_wg_key(stored, "stored private key")
            return validated or ""

        if not self.settings.generate_private_key:
            raise ConfigError("No WireGuard private key is available")

        generated = self.runner.run(["wg", "genkey"]).stdout.strip()
        validated = _validate_wg_key(generated, "generated private key")
        if not validated:
            raise CommandError("WireGuard did not generate a private key")
        atomic_write(PRIVATE_KEY_PATH, validated + "\n")
        logging.info("Generated and persisted a new client key pair")
        return validated

    def _write_key_files(self) -> None:
        self.private_key = self._read_or_generate_private_key()
        self.runner.secrets = tuple(
            secret
            for secret in (
                *self.settings.secrets,
                self.private_key,
            )
            if secret
        )
        atomic_write(RUNTIME_PRIVATE_KEY_PATH, self.private_key + "\n")
        public_key = self.runner.run(
            ["wg", "pubkey"], input_text=self.private_key + "\n"
        ).stdout.strip()
        _validate_wg_key(public_key, "derived public key")
        atomic_write(PUBLIC_KEY_PATH, public_key + "\n", mode=0o644)

        if self.settings.preshared_key:
            atomic_write(RUNTIME_PRESHARED_KEY_PATH, self.settings.preshared_key + "\n")

    def _enable_forwarding(self) -> None:
        forwarding_path = Path("/proc/sys/net/ipv4/ip_forward")
        try:
            forwarding_path.write_text("1\n", encoding="ascii")
        except OSError as err:
            raise CommandError("Could not enable IPv4 forwarding in the app container") from err

    def _apply_firewall(self) -> None:
        self.runner.run(
            ["nft", "delete", "table", NFT_FAMILY, NFT_TABLE], check=False
        )
        self.runner.run(["nft", "-f", "-"], input_text=build_nft_rules(self.settings))

    def _create_interface(self) -> None:
        kernel_result = self.runner.run(
            ["ip", "link", "add", INTERFACE, "type", "wireguard"], check=False
        )
        if kernel_result.returncode == 0:
            logging.info("Using the kernel WireGuard implementation")
            return

        logging.warning("Kernel WireGuard is unavailable; trying wireguard-go")
        environment = os.environ.copy()
        environment["WG_PROCESS_FOREGROUND"] = "1"
        try:
            self.userspace_process = subprocess.Popen(
                ["wireguard-go", INTERFACE],
                env=environment,
                text=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as err:
            raise CommandError("Could not start wireguard-go") from err

        for _ in range(50):
            if self.stop_event.wait(0.1):
                raise CommandError("WireGuard setup was interrupted")
            if self.userspace_process.poll() is not None:
                break
            if self.runner.run(
                ["ip", "link", "show", "dev", INTERFACE], check=False
            ).returncode == 0:
                logging.info("Using the userspace WireGuard implementation")
                return
        raise CommandError("wireguard-go did not create the WireGuard interface")

    def _configure_interface(self) -> None:
        command = [
            "wg",
            "set",
            INTERFACE,
            "private-key",
            str(RUNTIME_PRIVATE_KEY_PATH),
            "peer",
            self.settings.server_public_key,
        ]
        if self.settings.preshared_key:
            command.extend(["preshared-key", str(RUNTIME_PRESHARED_KEY_PATH)])
        command.extend(
            [
                "endpoint",
                self.settings.endpoint,
                "persistent-keepalive",
                str(self.settings.persistent_keepalive),
                "allowed-ips",
                ",".join(str(network) for network in self.settings.remote_subnets),
            ]
        )
        self.runner.run(command)
        self.runner.run(
            ["ip", "address", "add", str(self.settings.client_address), "dev", INTERFACE]
        )
        self.runner.run(
            ["ip", "link", "set", "dev", INTERFACE, "mtu", str(self.settings.mtu), "up"]
        )
        for network in self.settings.remote_subnets:
            self.runner.run(
                ["ip", "route", "replace", str(network), "dev", INTERFACE]
            )

    def start(self) -> None:
        self.runtime_status.update(
            phase="starting",
            configured=True,
            message="Der WireGuard-Tunnel wird aufgebaut.",
            endpoint=self.settings.endpoint,
            client_address=str(self.settings.client_address),
            remote_subnets=[str(item) for item in self.settings.remote_subnets],
            lan_targets=[str(item) for item in self.settings.lan_targets],
            latest_handshake=0,
            received_bytes=0,
            sent_bytes=0,
        )
        check_endpoint_routes(self.settings)
        self.stop()
        self._write_key_files()
        self._enable_forwarding()
        self._apply_firewall()
        self._create_interface()
        self._configure_interface()
        self.last_endpoint_refresh = time.monotonic()
        logging.info(
            "Tunnel is configured for %d remote subnet(s) and %d LAN target(s)",
            len(self.settings.remote_subnets),
            len(self.settings.lan_targets),
        )
        logging.info("The client public key is available in /config/public.key")

    def stop(self) -> None:
        self.runner.run(["ip", "link", "delete", INTERFACE], check=False)
        self.runner.run(
            ["nft", "delete", "table", NFT_FAMILY, NFT_TABLE], check=False
        )
        if self.userspace_process is not None:
            if self.userspace_process.poll() is None:
                self.userspace_process.terminate()
                try:
                    self.userspace_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.userspace_process.kill()
                    self.userspace_process.wait(timeout=5)
            self.userspace_process = None
        for path in (RUNTIME_PRIVATE_KEY_PATH, RUNTIME_PRESHARED_KEY_PATH):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def _status(self) -> tuple[int, int, int]:
        handshake_result = self.runner.run(
            ["wg", "show", INTERFACE, "latest-handshakes"]
        )
        transfer_result = self.runner.run(["wg", "show", INTERFACE, "transfer"])

        handshake = 0
        if handshake_result.stdout.strip():
            fields = handshake_result.stdout.strip().split()
            if len(fields) >= 2:
                handshake = int(fields[1])

        received = sent = 0
        if transfer_result.stdout.strip():
            fields = transfer_result.stdout.strip().split()
            if len(fields) >= 3:
                received = int(fields[1])
                sent = int(fields[2])
        return handshake, received, sent

    def _refresh_endpoint(self) -> None:
        check_endpoint_routes(self.settings)
        self.runner.run(
            [
                "wg",
                "set",
                INTERFACE,
                "peer",
                self.settings.server_public_key,
                "endpoint",
                self.settings.endpoint,
            ]
        )
        self.last_endpoint_refresh = time.monotonic()

    def monitor(self) -> None:
        while not self.stop_event.wait(5):
            if self.reload_event.is_set():
                return
            handshake, received, sent = self._status()
            now = int(time.time())
            handshake_age = now - handshake if handshake else None
            monotonic_now = time.monotonic()

            if handshake_age is None:
                phase = "waiting_handshake"
                message = "Tunnel bereit; es wurde noch kein Handshake empfangen."
            elif handshake_age <= 180:
                phase = "connected"
                message = "Der WireGuard-Tunnel ist verbunden."
            else:
                phase = "degraded"
                message = "Der letzte Handshake ist veraltet."
            self.runtime_status.update(
                phase=phase,
                message=message,
                latest_handshake=handshake,
                received_bytes=received,
                sent_bytes=sent,
            )

            if monotonic_now - self.last_status_log >= 300:
                if handshake_age is None:
                    logging.warning("No WireGuard handshake has been received yet")
                else:
                    logging.info(
                        "Tunnel status: handshake %ds ago, received %d bytes, sent %d bytes",
                        max(0, handshake_age),
                        received,
                        sent,
                    )
                self.last_status_log = monotonic_now

            if (
                (handshake_age is None or handshake_age > 180)
                and monotonic_now - self.last_endpoint_refresh >= 300
            ):
                logging.warning("Handshake is stale; refreshing the server endpoint")
                self._refresh_endpoint()


def configure_logging(level: str) -> None:
    numeric_level = getattr(logging, level.upper())
    if logging.getLogger().handlers:
        logging.getLogger().setLevel(numeric_level)
    else:
        logging.basicConfig(
            level=numeric_level,
            format="%(asctime)s %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


def wait_for_reload_or_stop(
    stop_event: threading.Event,
    reload_event: threading.Event,
    timeout: float | None = None,
) -> str:
    deadline = time.monotonic() + timeout if timeout is not None else None
    while not stop_event.wait(0.25):
        if reload_event.is_set():
            return "reload"
        if deadline is not None and time.monotonic() >= deadline:
            return "timeout"
    return "stop"


def run() -> int:
    configure_logging("info")
    stop_event = threading.Event()
    reload_event = threading.Event()
    runtime_status = RuntimeStatus()
    controller = AppController(runtime_status, reload_event)

    def request_stop(signum: int, _frame: Any) -> None:
        logging.info("Received signal %d; shutting down", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    try:
        web_server = IngressWebServer(controller)
        web_server.start()
    except OSError as err:
        logging.error("Could not start the ingress web interface: %s", err)
        return 1

    backoff = 2
    logging.info("Starting %s", APP_NAME)
    try:
        while not stop_event.is_set():
            reload_event.clear()
            try:
                settings, source = load_effective_settings()
            except ConfigError as err:
                imported_exists = IMPORTED_CONFIG_PATH.exists()
                runtime_status.update(
                    phase="configuration_error" if imported_exists else "unconfigured",
                    configured=False,
                    source="import" if imported_exists else "home_assistant",
                    message=(
                        str(err)
                        if imported_exists
                        else "Bitte eine WireGuard-Konfiguration über die Weboberfläche importieren."
                    ),
                    endpoint=None,
                    client_address=None,
                    remote_subnets=[],
                    lan_targets=[],
                    latest_handshake=0,
                    received_bytes=0,
                    sent_bytes=0,
                )
                logging.warning("Tunnel is not configured: %s", err)
                if wait_for_reload_or_stop(stop_event, reload_event) == "stop":
                    break
                continue

            configure_logging(settings.log_level)
            runtime_status.update(source=source, configured=True)
            router = WireGuardRouter(
                settings,
                stop_event,
                reload_event=reload_event,
                runtime_status=runtime_status,
            )
            try:
                router.start()
                backoff = 2
                router.monitor()
            except ConfigError as err:
                logging.error("Configuration error: %s", redact(str(err), settings.secrets))
                runtime_status.update(
                    phase="configuration_error",
                    message=redact(str(err), settings.secrets),
                )
                router.stop()
                if wait_for_reload_or_stop(stop_event, reload_event) == "stop":
                    break
            except (CommandError, OSError, ValueError) as err:
                safe_error = redact(str(err), settings.secrets)
                logging.error("Tunnel error: %s", safe_error)
                runtime_status.update(phase="error", message=safe_error)
                router.stop()
                if wait_for_reload_or_stop(
                    stop_event, reload_event, timeout=backoff
                ) == "stop":
                    break
                if not reload_event.is_set():
                    logging.info("Retrying tunnel setup")
                    backoff = min(backoff * 2, 60)
            else:
                router.stop()
    finally:
        runtime_status.update(phase="stopped", message="Das Add-on wurde gestoppt.")
        web_server.stop()
        logging.info("Ingress web interface stopped")
    return 0


if __name__ == "__main__":
    sys.exit(run())
