# Home Assistant WireGuard Client Router

This repository contains a Home Assistant app (formerly called an add-on) that
connects Home Assistant to an existing WireGuard server and provides carefully
limited access from remote WireGuard peers to selected devices in the Home
Assistant LAN.

The app is intentionally a **client and router**, not a WireGuard server. It:

- establishes an outbound tunnel, so the Home Assistant site normally needs no
  port forwarding;
- forwards only configured remote source networks to configured private LAN
  targets;
- uses NAT so no return route is needed on the home router;
- includes a Home Assistant Ingress dashboard with live tunnel status and a
  secure `.conf` upload/paste importer;
- does not use host networking, the Supervisor API, Docker access, or full
  container access;
- supports `amd64` and `aarch64` Home Assistant installations.

See the [app documentation](wireguard_client_router/DOCS.md) for installation,
configuration, and server-side routing examples.

## Status

The current release is an IPv4 MVP. IPv6 and routed mode without NAT are not
yet supported.

## Repository layout

```text
wireguard_client_router/
  app/                 Runtime, import API, web UI, and validation
  translations/        Home Assistant configuration UI translations
  config.yaml           App metadata and option schema
  Dockerfile            Multi-architecture container definition
  apparmor.txt          Restricted AppArmor profile
  DOCS.md               User documentation
tests/                   Unit tests for safety-critical configuration logic
```

## Development

Run the standard-library unit tests from the repository root:

```bash
python -m unittest discover -s tests -v
```

Build the app container locally:

```bash
docker build \
  --build-arg BUILD_VERSION=0.2.0 \
  --build-arg BUILD_ARCH=amd64 \
  -t ha-wireguard-client-router:dev \
  wireguard_client_router
```

Runtime networking tests must be performed on a Linux host with `NET_ADMIN`
and `/dev/net/tun`, or on a Home Assistant OS test installation.

## License

[MIT](LICENSE)
