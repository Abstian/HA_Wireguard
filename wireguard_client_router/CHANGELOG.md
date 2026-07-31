# Changelog

## 0.2.1

- Remove redundant Home Assistant metadata defaults reported by the app linter.

## 0.2.0

- Add a Home Assistant Ingress web interface with live tunnel status.
- Add secure WireGuard `.conf` upload and paste import with a validation preview.
- Add editable remote source networks and LAN targets before activation.
- Allow the app to start unconfigured so initial setup can happen in the web UI.
- Add automatic in-process reload and a switch back to Home Assistant options.

## 0.1.0

- Initial IPv4 WireGuard client-router release.
- Add fail-closed nftables forwarding and target-specific NAT.
- Add persistent generated keys and secret-safe diagnostics.
- Add configuration validation for unsafe routes and Home Assistant internal networks.
- Add `amd64` and `aarch64` support.
