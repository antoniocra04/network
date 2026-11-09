# Build
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/svyaz ./cmd/svyaz

# Run
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/svyaz /usr/local/bin/svyaz
ENV SVYAZ_DATA=/data \
    SVYAZ_CONFIG=/data/config.yaml \
    SVYAZ_LISTEN=:8080
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD wget -qO- http://127.0.0.1:${SVYAZ_LISTEN#:}/healthz >/dev/null || exit 1
# Runs as root inside the container: raw ICMP sockets need CAP_NET_RAW,
# which compose grants while dropping every other capability.
ENTRYPOINT ["/usr/local/bin/svyaz"]
