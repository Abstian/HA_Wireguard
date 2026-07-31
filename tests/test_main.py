import base64
import http.client
import importlib.util
import ipaddress
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "wireguard_client_router"
    / "app"
    / "main.py"
)
SPEC = importlib.util.spec_from_file_location("wireguard_client_router_main", MODULE_PATH)
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


VALID_KEY = base64.b64encode(bytes(range(32))).decode()
OTHER_VALID_KEY = base64.b64encode(bytes(range(1, 33))).decode()


def valid_wireguard_config():
    return f"""# Exported client configuration
[Interface]
PrivateKey = {OTHER_VALID_KEY}
Address = 10.40.0.2/32
DNS = 10.40.0.1
MTU = 1380

[Peer]
PublicKey = {VALID_KEY}
PresharedKey = {OTHER_VALID_KEY}
Endpoint = vpn.example.test:51820
AllowedIPs = 10.40.0.0/24, 192.168.178.0/24, 0.0.0.0/0
PersistentKeepalive = 25
"""


def valid_options():
    return {
        "server": {
            "endpoint": "vpn.example.test:51820",
            "public_key": VALID_KEY,
        },
        "client": {
            "address": "10.40.0.2/32",
            "generate_private_key": True,
        },
        "routing": {
            "remote_subnets": ["10.40.0.0/24"],
            "lan_targets": ["192.168.178.20/32", "192.168.178.0/24"],
            "masquerade": True,
        },
        "wireguard": {"persistent_keepalive": 25, "mtu": 1420},
        "log_level": "info",
    }


class SettingsTests(unittest.TestCase):
    def load(self, options):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "options.json"
            path.write_text(json.dumps(options), encoding="utf-8")
            return module.load_settings(path)

    def test_loads_valid_settings_and_deduplicates_networks(self):
        options = valid_options()
        options["routing"]["remote_subnets"].append("10.40.0.0/24")
        settings = self.load(options)

        self.assertEqual(settings.endpoint_host, "vpn.example.test")
        self.assertEqual(settings.client_address.ip, ipaddress.ip_address("10.40.0.2"))
        self.assertEqual(settings.remote_subnets, (ipaddress.ip_network("10.40.0.0/24"),))

    def test_rejects_default_route(self):
        options = valid_options()
        options["routing"]["remote_subnets"] = ["0.0.0.0/0"]

        with self.assertRaisesRegex(module.ConfigError, "0.0.0.0/0"):
            self.load(options)

    def test_rejects_public_lan_target(self):
        options = valid_options()
        options["routing"]["lan_targets"] = ["8.8.8.8/32"]

        with self.assertRaisesRegex(module.ConfigError, "RFC1918"):
            self.load(options)

    def test_rejects_public_remote_route(self):
        options = valid_options()
        options["routing"]["remote_subnets"] = ["8.0.0.0/8"]

        with self.assertRaisesRegex(module.ConfigError, "RFC6598"):
            self.load(options)

    def test_rejects_home_assistant_internal_network(self):
        options = valid_options()
        options["routing"]["lan_targets"] = ["172.30.32.2/32"]

        with self.assertRaisesRegex(module.ConfigError, "Home Assistant internal"):
            self.load(options)

    def test_rejects_overlapping_source_and_target(self):
        options = valid_options()
        options["routing"]["remote_subnets"] = ["192.168.178.128/25"]

        with self.assertRaisesRegex(module.ConfigError, "must not overlap"):
            self.load(options)

    def test_rejects_noncanonical_target(self):
        options = valid_options()
        options["routing"]["lan_targets"] = ["192.168.178.20/24"]

        with self.assertRaisesRegex(module.ConfigError, "non-canonical"):
            self.load(options)

    def test_requires_private_key_when_generation_is_off(self):
        options = valid_options()
        options["client"]["generate_private_key"] = False

        with self.assertRaisesRegex(module.ConfigError, "private_key is required"):
            self.load(options)

    def test_accepts_supplied_private_and_preshared_keys(self):
        options = valid_options()
        options["client"]["generate_private_key"] = False
        options["client"]["private_key"] = OTHER_VALID_KEY
        options["server"]["preshared_key"] = VALID_KEY

        settings = self.load(options)

        self.assertEqual(settings.private_key, OTHER_VALID_KEY)
        self.assertEqual(settings.preshared_key, VALID_KEY)


class FirewallTests(unittest.TestCase):
    def test_firewall_is_fail_closed_and_target_specific(self):
        settings_test = SettingsTests()
        settings = settings_test.load(valid_options())
        rules = module.build_nft_rules(settings)

        self.assertIn("policy drop", rules)
        self.assertIn('iifname "wg0" oifname "eth0"', rules)
        self.assertIn("ip saddr @remote_v4 ip daddr @lan_v4", rules)
        self.assertIn("ct state established,related accept", rules)
        self.assertIn("masquerade", rules)
        self.assertNotIn("0.0.0.0/0", rules)


class ForwardingTests(unittest.TestCase):
    def setUp(self):
        self.router = object.__new__(module.WireGuardRouter)

    def test_does_not_write_when_forwarding_is_already_enabled(self):
        forwarding_path = mock.Mock()
        forwarding_path.read_text.return_value = "1\n"

        with mock.patch.object(module, "IPV4_FORWARD_PATH", forwarding_path):
            self.router._enable_forwarding()

        forwarding_path.write_text.assert_not_called()

    def test_enables_and_verifies_disabled_forwarding(self):
        forwarding_path = mock.Mock()
        forwarding_path.read_text.side_effect = ["0\n", "1\n"]

        with mock.patch.object(module, "IPV4_FORWARD_PATH", forwarding_path):
            self.router._enable_forwarding()

        forwarding_path.write_text.assert_called_once_with("1\n", encoding="ascii")

    def test_reports_host_action_when_disabled_state_is_read_only(self):
        forwarding_path = mock.Mock()
        forwarding_path.read_text.return_value = "0\n"
        forwarding_path.write_text.side_effect = OSError("read-only file system")

        with mock.patch.object(module, "IPV4_FORWARD_PATH", forwarding_path):
            with self.assertRaisesRegex(
                module.CommandError, "enable net.ipv4.ip_forward=1 on the host"
            ):
                self.router._enable_forwarding()


class EndpointTests(unittest.TestCase):
    def test_rejects_endpoint_inside_remote_route(self):
        settings_test = SettingsTests()
        settings = settings_test.load(valid_options())

        with mock.patch.object(
            module,
            "resolve_endpoint",
            return_value=(ipaddress.ip_address("10.40.0.10"),),
        ):
            with self.assertRaisesRegex(module.ConfigError, "routing loop"):
                module.check_endpoint_routes(settings)


class SecretTests(unittest.TestCase):
    def test_redacts_all_secret_values(self):
        message = f"private={VALID_KEY} psk={OTHER_VALID_KEY}"
        redacted = module.redact(message, (VALID_KEY, OTHER_VALID_KEY))

        self.assertNotIn(VALID_KEY, redacted)
        self.assertNotIn(OTHER_VALID_KEY, redacted)
        self.assertEqual(redacted.count("[REDACTED]"), 2)


class WireGuardImportTests(unittest.TestCase):
    def test_parses_config_and_suggests_safe_routes(self):
        imported = module.parse_wireguard_config(valid_wireguard_config())

        self.assertEqual(imported.endpoint, "vpn.example.test:51820")
        self.assertEqual(imported.client_address, "10.40.0.2/32")
        self.assertEqual(imported.mtu, 1380)
        self.assertEqual(imported.suggested_remote_subnets, ("10.40.0.0/24",))
        self.assertEqual(imported.suggested_lan_targets, ("192.168.178.0/24",))
        self.assertTrue(any("0.0.0.0/0" in warning for warning in imported.warnings))

    def test_preview_does_not_return_secret_key_material(self):
        preview = module.parse_wireguard_config(valid_wireguard_config()).preview()
        serialized = json.dumps(preview)

        self.assertNotIn(OTHER_VALID_KEY, serialized)
        self.assertNotIn(VALID_KEY, serialized)
        self.assertTrue(preview["has_private_key"])
        self.assertTrue(preview["has_preshared_key"])

    def test_rejects_script_directives(self):
        config = valid_wireguard_config().replace(
            "MTU = 1380", "MTU = 1380\nPostUp = curl https://example.test"
        )

        with self.assertRaisesRegex(module.ConfigError, "Sicherheitsgründen"):
            module.parse_wireguard_config(config)

    def test_rejects_multiple_peers(self):
        config = valid_wireguard_config() + f"\n[Peer]\nPublicKey = {VALID_KEY}\n"

        with self.assertRaisesRegex(module.ConfigError, r"genau einen \[Peer\]"):
            module.parse_wireguard_config(config)

    def test_imported_options_pass_runtime_validation(self):
        imported = module.parse_wireguard_config(valid_wireguard_config())
        options = module.imported_options(
            imported,
            ["10.40.0.0/24"],
            ["192.168.178.0/24"],
        )

        settings = module.settings_from_options(options)
        self.assertEqual(settings.private_key, OTHER_VALID_KEY)
        self.assertEqual(settings.lan_targets, (ipaddress.ip_network("192.168.178.0/24"),))


class ControllerTests(unittest.TestCase):
    def test_apply_persists_config_and_requests_reload(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "imported.json"
            reload_event = module.threading.Event()
            controller = module.AppController(
                module.RuntimeStatus(), reload_event, imported_path=path
            )

            result = controller.apply_import(
                {
                    "config_text": valid_wireguard_config(),
                    "remote_subnets": ["10.40.0.0/24"],
                    "lan_targets": ["192.168.178.0/24"],
                }
            )

            self.assertTrue(result["ok"])
            self.assertTrue(reload_event.is_set())
            self.assertTrue(path.exists())
            module.settings_from_options(json.loads(path.read_text(encoding="utf-8")))

            reload_event.clear()
            controller.reset_import()
            self.assertFalse(path.exists())
            self.assertTrue(reload_event.is_set())


class IngressApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.reload_event = module.threading.Event()
        self.controller = module.AppController(
            module.RuntimeStatus(),
            self.reload_event,
            imported_path=Path(self.temporary_directory.name) / "imported.json",
        )
        self.server = module.IngressWebServer(
            self.controller,
            host="127.0.0.1",
            port=0,
            web_root=MODULE_PATH.parent / "web",
        )
        self.server.start()

    def tearDown(self):
        self.server.stop()
        self.temporary_directory.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        content = response.read()
        connection.close()
        return response.status, dict(response.headers), content

    def test_rejects_direct_non_ingress_access(self):
        with mock.patch.dict(module.os.environ, {"ALLOW_NON_INGRESS": "0"}):
            status, _headers, _content = self.request("GET", "/api/status")
        self.assertEqual(status, 403)

    def test_serves_ingress_ui_with_dynamic_base_path(self):
        with mock.patch.dict(module.os.environ, {"ALLOW_NON_INGRESS": "1"}):
            status, headers, content = self.request(
                "GET",
                "/",
                headers={"X-Ingress-Path": "/api/hassio_ingress/example"},
            )

        self.assertEqual(status, 200)
        self.assertIn("Content-Security-Policy", headers)
        self.assertIn(
            b'<base href="/api/hassio_ingress/example/">',
            content,
        )
        self.assertIn(b"WireGuard Router", content)

    def test_preview_api_never_returns_secrets(self):
        body = json.dumps({"config_text": valid_wireguard_config()})
        with mock.patch.dict(module.os.environ, {"ALLOW_NON_INGRESS": "1"}):
            status, _headers, content = self.request(
                "POST",
                "/api/import/preview",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body.encode("utf-8"))),
                    "X-WG-Request": "1",
                },
            )

        self.assertEqual(status, 200)
        self.assertNotIn(OTHER_VALID_KEY.encode(), content)
        self.assertNotIn(VALID_KEY.encode(), content)
        payload = json.loads(content)
        self.assertEqual(payload["endpoint"], "vpn.example.test:51820")


if __name__ == "__main__":
    unittest.main()
