FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables tcpdump iputils-ping \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
