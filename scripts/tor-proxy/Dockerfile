FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tor torsocks wget \
    && rm -rf /var/lib/apt/lists/*

COPY torrc /etc/tor/torrc

EXPOSE 9050

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD torsocks wget -qO- https://check.torproject.org/api/ip >/dev/null 2>&1 || exit 1

CMD ["tor", "-f", "/etc/tor/torrc"]
