ARG BUILD_FROM=ghcr.io/home-assistant/base:3.23
FROM ${BUILD_FROM}

ARG BUILD_VERSION=dev
ARG BUILD_ARCH=amd64

RUN apk add --no-cache \
        iproute2 \
        nftables \
        python3 \
        wireguard-go \
        wireguard-tools

COPY app /app
COPY run.sh /run.sh

RUN chmod 0755 /run.sh \
    && python3 -m compileall -q /app

CMD ["/run.sh"]

LABEL \
    io.hass.version="${BUILD_VERSION}" \
    io.hass.type="app" \
    io.hass.arch="${BUILD_ARCH}" \
    org.opencontainers.image.title="Home Assistant App: WireGuard Client Router" \
    org.opencontainers.image.description="Outbound WireGuard client with restricted IPv4 LAN routing" \
    org.opencontainers.image.source="https://github.com/Abstian/HA_Wireguard" \
    org.opencontainers.image.licenses="MIT"
