ARG SINGBOX_VERSION=1.15.0-alpha.13
ARG ENABLE_UPX=1

FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine AS gobuild
ARG TARGETOS
ARG ENABLE_UPX
ARG TARGETARCH
ARG TARGETVARIANT
RUN apk add --no-cache file upx
WORKDIR /src
COPY go/healthcheck/ ./healthcheck/
RUN case "$TARGETVARIANT" in v7) export GOARM=7 ;; v6) export GOARM=6 ;; esac \
 && cd /src/healthcheck && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags='-s -w -buildid=' -o /out/healthcheck . \
 && file /out/healthcheck \
 && if [ "$ENABLE_UPX" = "1" ]; then upx -9 /out/healthcheck; fi

FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine AS sbbuild
ARG SINGBOX_VERSION
ARG TARGETOS
ARG ENABLE_UPX
ARG TARGETARCH
ARG TARGETVARIANT
RUN apk add --no-cache git file upx
WORKDIR /src
RUN git clone --depth 1 --branch "v${SINGBOX_VERSION}" https://github.com/SagerNet/sing-box.git
WORKDIR /src/sing-box
RUN case "$TARGETVARIANT" in v7) export GOARM=7 ;; v6) export GOARM=6 ;; esac \
 && RELEASE_LDFLAGS="$(cat release/LDFLAGS 2>/dev/null || printf '%s' '-s -w -buildid=')" \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -buildid= -X github.com/sagernet/sing-box/constant.Version=v${SINGBOX_VERSION} $RELEASE_LDFLAGS" \
        -tags 'with_quic,with_grpc,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0' \
        -o /out/sing-box ./cmd/sing-box \
 && file /out/sing-box \
 && ls -lh /out/sing-box \
 && if [ "$ENABLE_UPX" = "1" ]; then upx -9 /out/sing-box; fi

FROM alpine:3.23

LABEL org.opencontainers.image.source="https://github.com/inlarin/hynet-singbox-public" \
      org.opencontainers.image.description="sing-box single-pool VPN client packaged for MikroTik RouterOS containers (subscription-driven, zero NAND-wear, slim build)" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="hynet-singbox" \
      org.opencontainers.image.url="https://github.com/inlarin/hynet-singbox-public"

RUN apk add --no-cache ca-certificates tini iproute2-minimal \
 && rm -rf /var/cache/apk/*
COPY --from=gobuild /out/healthcheck /usr/local/bin/healthcheck
COPY --from=sbbuild /out/sing-box    /usr/local/bin/sing-box
COPY scripts/entrypoint.sh   /usr/local/bin/entrypoint.sh
COPY scripts/sub-refresh.sh  /usr/local/bin/sub-refresh.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/sub-refresh.sh \
 && mkdir -p /opt/etc/sing-box/subscriptions.d

ENV REFRESH_INTERVAL=86400 \
    SINGBOX_TUN_NAME=opkgtun0 \
    SINGBOX_TUN_STACK=none \
    TUN_ADDR=172.19.0.1 \
    TUN_MTU=1420 \
    CLASH_ADDR=172.20.0.2:9090 \
    ROUTER_HOST=172.20.0.1 \
    SINGBOX_NODE_RESOLVER=172.20.0.1 \
    EXCLUDE_AUTO_CC=RU \
    SINGBOX_EXCLUDE_AUTO_PROTO=shadowsocks,vmess \
    SINGBOX_UTLS_FINGERPRINT=chrome \
    HEALTHCHECK_ENABLED=1 \
    LIVENESS_URL=https://speed.cloudflare.com/__down?bytes=100000 \
    LIVENESS_BYTES=100000 \
    LIVENESS_INTERVAL=30s \
    RANK_INTERVAL=10m \
    RANK_STALE_AFTER=25m \
    PROBE_TIMEOUT=12s \
    PROBE_CONCURRENCY=4 \
    FAIL_THRESHOLD=2 \
    HYSTERESIS_PCT=15 \
    SEVERE_IMPROVE_PCT=50 \
    FAILOVER_CANDIDATES=5 \
    MIN_SWITCH_INTERVAL=15m \
    IMPROVE_CONFIRMATIONS=2 \
    AUTO_PIN=1 \
    TELEGRAM_HEALTHCHECK=1 \
    TELEGRAM_API_URL=https://api.telegram.org \
    MTPROTO_ADDRESS=149.154.167.50:80 \
    PROBE_COUNTRIES=/tmp/probe_countries.json \
    ROTATIONS_BEFORE_FORCE_SWEEP=3 \
    TMPFS_SIZE=64M \
    GOGC=50 \
    GOMEMLIMIT=96MiB

EXPOSE 9090
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
