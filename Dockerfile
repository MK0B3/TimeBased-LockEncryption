# syntax=docker/dockerfile:1

# ---- build stage ----------------------------------------------------------
FROM golang:1.24-alpine AS build

WORKDIR /src

# Dependencies are copied first so that editing source does not invalidate the
# module download layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO is disabled so the result is a static binary that runs on a bare runtime
# image without pulling in libc.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/server ./cmd/server

# ---- runtime stage --------------------------------------------------------
FROM alpine:3.20

# The server fetches beacons from https://api.drand.sh. Without root
# certificates that fails at startup with an opaque x509 error, so install them
# explicitly rather than inheriting them by luck.
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 capsule

WORKDIR /app

COPY --from=build /out/server /app/server

# Gin resolves ./web/templates and ./web/static at request time, relative to the
# working directory. A binary-only image would build fine and then serve errors
# on every page, so the assets have to ship next to it.
COPY web/ /app/web/

RUN mkdir -p /app/data && chown -R capsule:capsule /app

USER capsule

# SERVER_HOST defaults to localhost in the application. Inside a container that
# binds to the container's own loopback, which makes a published port resolve to
# nothing. Bind to all interfaces instead; the port mapping is what controls
# exposure.
ENV SERVER_HOST=0.0.0.0 \
    SERVER_PORT=8080 \
    DB_PATH=/app/data/capsules.db

EXPOSE 8080

# Capsules live in a BoltDB file; without a volume they vanish with the container.
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -q -O- http://127.0.0.1:8080/api/health || exit 1

ENTRYPOINT ["/app/server"]
