# syntax=docker/dockerfile:1
# One image, three binaries. Which binary a subcontainer runs and what it can
# see is decided by startos/main.ts, not here.

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY service/go.mod service/go.sum* ./
# go.sum is committed once `go mod tidy` has run on a machine with module
# access; -mod=mod lets a first build resolve it without failing.
ENV GOFLAGS=-mod=mod CGO_ENABLED=0
RUN go mod download || true
COPY service/ ./
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/edge ./cmd/edge \
 && GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/core ./cmd/core \
 && GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/guard ./cmd/guard

FROM alpine:3.22
# The base image ships the Mozilla roots (ca-certificates-bundle), which
# core verifies public wss:// relays against; it adds the StartOS root CA at
# runtime for relays on this box.
# Three uids, matching startos/utils.ts. No shells for them, no home dirs.
RUN adduser -D -H -u 1001 -s /sbin/nologin edge \
 && adduser -D -H -u 1002 -s /sbin/nologin core \
 && adduser -D -H -u 1003 -s /sbin/nologin guard \
 && mkdir -p /etc/lightning-identity /run/lightning-identity /identities /credentials /guard /core /edge /site /upload /lnd/admin
COPY --from=build /out/edge /out/core /out/guard /usr/local/bin/
COPY assets/prepare-volume.sh /usr/local/bin/prepare-volume.sh
RUN chmod 0755 /usr/local/bin/edge /usr/local/bin/core /usr/local/bin/guard /usr/local/bin/prepare-volume.sh
# No ENTRYPOINT: each daemon names its binary explicitly.
