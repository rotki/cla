# --- Build ---
# On the build machine's own platform: Go cross-compiles for the target, so
# a multi-platform build needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG GIT_SHA=unknown
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH
# -trimpath keeps build machine paths out of the binaries, so the same
# sources give the same binaries wherever they are built.
RUN export CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
 && go build -trimpath \
    -ldflags="-s -w -X github.com/rotki/cla/internal/version.Version=${VERSION} -X github.com/rotki/cla/internal/version.GitSHA=${GIT_SHA}" \
    -o server ./cmd/cla-server \
 && go build -trimpath -ldflags="-s -w" -o cla-tool ./cmd/cla-tool \
 && mkdir -p /out/data /out/backups

# --- Final ---
FROM scratch
ARG GIT_SHA=unknown
ARG VERSION=dev
ARG BUILD_DATE

LABEL org.opencontainers.image.title="cla"
LABEL org.opencontainers.image.description="Contributor License Agreement checks and signing for the rotki GitHub organization"
LABEL org.opencontainers.image.source="https://github.com/rotki/cla"
LABEL org.opencontainers.image.url="https://rotki.com"
LABEL org.opencontainers.image.vendor="Rotki Solutions GmbH"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /build/server /server
# For maintenance inside the container: docker compose exec cla /cla-tool verify
COPY --from=build /build/cla-tool /cla-tool
# The data directory: signatures, settings and the audit log. Owned by the
# service user, so a new named volume mounted here starts out writable.
COPY --from=build --chown=65532:65532 --chmod=750 /out/data /data
ENV DATA_DIR=/data
VOLUME ["/data"]
# Where the service drops verified archives for the backup job (BACKUP_DIR).
# Not a VOLUME: it stays off until BACKUP_DIR is set and a volume mounted.
COPY --from=build --chown=65532:65532 --chmod=750 /out/backups /backups
# Numeric because scratch has no /etc/passwd.
USER 65532:65532
EXPOSE 4000
# During the start period it checks every 2 s, so after a restart the new
# copy is marked healthy, and receives traffic, within seconds rather than
# after the first 30 s interval (needs Docker Engine 25 or later; older ones
# ignore it).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --start-interval=2s --retries=3 \
  CMD ["/server", "healthcheck"]
ENTRYPOINT ["/server"]
