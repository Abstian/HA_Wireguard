# WireGuard Client Router

This app creates an outbound WireGuard connection to an existing server and
acts as a restricted IPv4 gateway into the Home Assistant LAN.

## Before you start

You need:

- Home Assistant OS or a supervised Home Assistant installation on `amd64` or
  `aarch64`;
- the WireGuard server endpoint and public key;
- a free `/32` address in the WireGuard tunnel;
- the tunnel addresses used by the remote peers;
- the private LAN targets that should be reachable.

The current release supports IPv4 and NAT only. It does not route all internet
traffic and deliberately rejects `0.0.0.0/0`.

## Installation

1. In Home Assistant, open **Settings → Apps → App store**.
2. Open the repository menu and add
   `https://github.com/Abstian/HA_Wireguard`.
3. Install **WireGuard Client Router**.
4. Start the app without entering connection data.
5. Select **Open Web UI** and import a WireGuard client configuration.

No inbound port forwarding is normally required at the Home Assistant site,
because the tunnel is initiated from the app to the server.

## Importing a WireGuard configuration in the web UI

The **Open Web UI** button opens an authenticated Home Assistant Ingress page.
It provides live handshake and transfer status and a three-step import:

1. Upload a `.conf` file or paste its text.
2. Review the parsed endpoint, client address, `AllowedIPs`, and suggested
   routes. Secret keys are never returned by the preview API.
3. Confirm the remote WireGuard source networks and the private LAN targets,
   then activate the configuration.

The importer supports one `[Interface]` and one `[Peer]`. It reads
`PrivateKey`, `Address`, `MTU`, `PublicKey`, `PresharedKey`, `Endpoint`,
`AllowedIPs`, and `PersistentKeepalive`. IPv6 values are ignored with a
warning. `PreUp`, `PostUp`, `PreDown`, and `PostDown` are rejected rather than
executed.

The uploaded file itself is not stored. Its validated values are written with
mode `0600` to the app-specific `/config/imported_config.json`. An imported
configuration overrides the Home Assistant option fields until **Remove
import** is selected in the overview.

`AllowedIPs = 0.0.0.0/0` is shown as a warning and is never activated. The
importer suggests likely tunnel and LAN networks, but they must be reviewed
before saving because a standard WireGuard file does not describe this app's
source/destination firewall policy.

## Manual Home Assistant configuration

As an alternative to the web importer, all connection values can still be
entered on the app's **Configuration** tab.

Example for a WireGuard network `10.40.0.0/24` and a home network
`192.168.178.0/24`:

```yaml
server:
  endpoint: vpn.example.de:51820
  public_key: PUBLIC_KEY_OF_THE_SERVER
client:
  address: 10.40.0.2/32
  generate_private_key: true
routing:
  remote_subnets:
    - 10.40.0.0/24
  lan_targets:
    - 192.168.178.0/24
  masquerade: true
wireguard:
  persistent_keepalive: 25
  mtu: 1420
log_level: info
```

To expose only individual devices, use `/32` targets:

```yaml
routing:
  remote_subnets:
    - 10.40.0.0/24
  lan_targets:
    - 192.168.178.20/32
    - 192.168.178.30/32
  masquerade: true
```

### `server.endpoint`

Hostname or IP address and UDP port of the existing WireGuard server. IPv6
endpoints use bracket notation, for example `[2001:db8::10]:51820`.

### `server.public_key`

The server's WireGuard public key.

### `server.preshared_key`

Optional WireGuard preshared key. Configure the same value for this peer on the
server. The app never prints private or preshared keys in its log.

### `client.address`

The IPv4 `/32` tunnel address assigned to Home Assistant. It must be unique on
the WireGuard server.

### `client.private_key` and `client.generate_private_key`

Leave `private_key` empty and keep `generate_private_key: true` for the easiest
setup. On first start, the app stores:

- `/config/private.key` — private key, mode `0600`;
- `/config/public.key` — public key to copy to the WireGuard server.

`/config` is the app-specific directory below Home Assistant's
`/addon_configs` directory. Existing generated keys are reused after restarts
and updates. Supplying `client.private_key` overrides the persisted private key.

### `routing.remote_subnets`

Source networks used by remote WireGuard peers. These networks become both the
peer's WireGuard `AllowedIPs` and the return routes through `wg0`.

Use RFC1918 private or RFC6598 shared (`100.64.0.0/10`) tunnel addresses. Do not
put the home LAN here. Do not include the public server endpoint.

### `routing.lan_targets`

Private RFC1918 LAN networks or individual `/32` devices that remote peers may
reach. The firewall drops all other forwarded traffic. Home Assistant's
internal app network is always rejected.

### `routing.masquerade`

Must be `true` in this release. LAN devices see the Home Assistant host as the
source, so the home router needs no static return route.

### `wireguard.persistent_keepalive`

`25` seconds is recommended when Home Assistant is behind NAT. Set `0` only
when keepalives are not needed.

### `wireguard.mtu`

`1420` works for most internet links. Try `1380` if handshakes work but larger
connections stall.

## WireGuard server configuration

After the app has started once, read its generated `public.key` and add a peer
to the existing WireGuard server. The server must route both the Home Assistant
tunnel address and every LAN target to this peer:

```ini
[Peer]
PublicKey = PUBLIC_KEY_FROM_HOME_ASSISTANT
AllowedIPs = 10.40.0.2/32, 192.168.178.0/24
```

Do not add an `Endpoint` for the Home Assistant peer on the server when its
public address is dynamic. WireGuard learns it from the outbound connection.

The server must also allow forwarding between its WireGuard peers. How this is
enabled depends on the server distribution and its existing firewall.

## Remote peer configuration

Every remote client that should access the LAN needs the LAN target in its own
`AllowedIPs`:

```ini
[Peer]
PublicKey = PUBLIC_KEY_OF_THE_SERVER
Endpoint = vpn.example.de:51820
AllowedIPs = 10.40.0.0/24, 192.168.178.0/24
PersistentKeepalive = 25
```

Use narrower `/32` entries when only specific devices should be accessible.

## Packet path and security boundary

Traffic is accepted only when all of the following are true:

1. it arrives through `wg0`;
2. its source is in `remote_subnets`;
3. its destination is in `lan_targets`;
4. it leaves through the app's `eth0` interface.

Only established reply traffic is admitted in the opposite direction. NAT is
limited to that same source/destination pair. The app has no host networking,
Supervisor API, Docker socket, or full-access permission.

## Troubleshooting

### No handshake

- Verify endpoint, UDP port, and both public keys.
- Verify that the server permits UDP on its WireGuard port.
- Confirm that the server peer uses the Home Assistant public key from
  `/config/public.key`.
- If a preshared key is configured, verify it on both sides.

### Handshake works, LAN target does not respond

- Add the LAN target to the Home Assistant peer's `AllowedIPs` on the server.
- Add the LAN target to the remote client's `AllowedIPs`.
- Enable peer-to-peer forwarding on the server.
- Verify that the target is in `routing.lan_targets`.
- Check a host firewall on the target device. With NAT, it sees the connection
  as coming from the Home Assistant host.

### IPv4 forwarding is disabled

On Home Assistant OS, IPv4 forwarding is normally already enabled. The app
reads and reuses that state without attempting to modify the read-only sysctl
mount. On a Supervised installation where it is disabled, enable
`net.ipv4.ip_forward=1` persistently on the Linux host and restart the app.

### Small packets work, larger connections stall

Reduce `wireguard.mtu`, for example from `1420` to `1380`.

### App reports a routing-loop error

The server endpoint resolved to an address covered by `remote_subnets`. Make
the remote source range narrower or use an endpoint outside that range.

### Kernel WireGuard is unavailable

The app automatically falls back to `wireguard-go` through `/dev/net/tun`.
This is slower but functionally equivalent for this use case.

## Current limitations

- IPv4 only.
- NAT is mandatory.
- One WireGuard server peer.
- Imported configurations must contain exactly one interface and one peer.
