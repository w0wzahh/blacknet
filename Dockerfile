# Blacknet — multi-stage build (backend + frontend)
FROM node:22-alpine AS web
WORKDIR /build/web
COPY web/package.json web/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS go
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /blacknet ./cmd/blacknet

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -H -u 1000 blacknet
WORKDIR /app
COPY --from=go /blacknet /app/blacknet
COPY --from=web /build/web/dist /app/web/dist
COPY config.example.yaml /app/config.yaml
RUN mkdir -p /data && chown blacknet:blacknet /data
ENV BLACKNET_CONFIG=/app/config.yaml
# DNS requires binding to 53 — run as root in the container (standard for DNS
# servers) or map a high port. The container default keeps root inside the
# container only; no host privileges are needed beyond the port mapping.
EXPOSE 53/udp 53/tcp 8080/tcp
VOLUME /data
ENTRYPOINT ["/app/blacknet"]
CMD ["serve", "--config", "/app/config.yaml"]
