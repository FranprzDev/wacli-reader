FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -o /reader .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/w.tgz https://github.com/openclaw/wacli/releases/download/v0.26.0/wacli_0.26.0_linux_amd64.tar.gz \
 && echo "2c28f65e2f9aaf32585288229db1f916c6c5fb5db9513715017d528513604b44  /tmp/w.tgz" | sha256sum -c - \
 && tar -xzf /tmp/w.tgz -C /tmp wacli && install -m 0755 /tmp/wacli /usr/local/bin/wacli && rm -f /tmp/w.tgz /tmp/wacli
COPY --from=build /reader /usr/local/bin/reader
RUN useradd -m -u 10001 app
USER app
ENV WACLI_STORE_DIR=/tmp/wacli-store
CMD ["/usr/local/bin/reader"]
