FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-tk xvfb bash ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY chimera/chimera-ui /app/chimera-ui
