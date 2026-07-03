FROM kalilinux/kali-rolling

ARG ENABLE_ML=0
ARG ENABLE_PLAYWRIGHT=0
ARG ENABLE_SECURITY=0
ARG ENABLE_VIBE=0
ARG ENABLE_DECEPTICON=0
ARG ENABLE_SHANNON=0
ARG ENABLE_ZYPHERON=0
ARG ENABLE_ZYPHERON_ML=0
ARG ENABLE_SUBFINDER=0

RUN apt-get update && apt-get install -y \
    python3 python3-venv python3-pip python3-dev \
    bash ca-certificates git \
    build-essential pkg-config \
    libssl-dev libffi-dev \
    libxml2-dev libxslt1-dev \
    libjpeg-dev zlib1g-dev \
    libpq-dev \
    libpcap-dev \
    libgmp-dev libmpfr-dev binutils \
    poppler-utils \
    docker.io \
    nmap masscan nikto \
    curl wget \
 && rm -rf /var/lib/apt/lists/*

# ── Install Go 1.23 (Kali's golang-go may be too old for projectdiscovery tools)
RUN curl -fsSL https://go.dev/dl/go1.23.8.linux-amd64.tar.gz \
      | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:$PATH"

WORKDIR /app

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PLAYWRIGHT_BROWSERS_PATH="/ms-playwright"

COPY chimera/chimera-core/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --upgrade --force-reinstall -r /tmp/requirements.txt
RUN mkdir -p "${PLAYWRIGHT_BROWSERS_PATH}" \
 && playwright install --with-deps chromium

COPY tools/strix /app/tools/strix
RUN pip3 install --no-cache-dir -e /app/tools/strix

COPY tools/autoswagger/requirements.txt /tmp/requirements-autoswagger.txt
COPY tools/vibe-pentester/requirements.txt /tmp/requirements-vibepentester.txt
COPY tools/decepticon/requirements.txt /tmp/requirements-decepticon.txt
COPY tools/zypheron/zypheron-ai/requirements.txt /tmp/requirements-zypheron.txt
COPY tools/zypheron/zypheron-ai/requirements-ml.txt /tmp/requirements-zypheron-ml.txt
COPY tools/zypheron/zypheron-ai/requirements-security.txt /tmp/requirements-zypheron-security.txt
COPY tools/zypheron/zypheron-ai/requirements-web.txt /tmp/requirements-zypheron-web.txt
COPY tools/zypheron/zypheron-ai/requirements-mcp.txt /tmp/requirements-zypheron-mcp.txt
# tools/shannon upstream restructured away from python/ layout; stub files keep
# the ENABLE_SHANNON / ENABLE_PLAYWRIGHT conditional installs below from failing.
# Replace with real COPY once the shannon submodule path is updated.
RUN echo "# shannon-llm placeholder" > /tmp/requirements-shannon-llm.txt \
 && echo "# shannon-playwright placeholder" > /tmp/requirements-shannon-playwright.txt

RUN awk '!/^(torch|transformers|scikit-learn|spacy|nltk|pandas|numpy)[<>= ]/' \
      /tmp/requirements-zypheron.txt > /tmp/requirements-zypheron-base.txt

RUN pip3 install --no-cache-dir \
    -r /tmp/requirements-autoswagger.txt \
    -r /tmp/requirements-zypheron-mcp.txt

RUN if [ "$ENABLE_VIBE" = "1" ]; then \
      pip3 install --no-cache-dir -r /tmp/requirements-vibepentester.txt; \
    fi

RUN if [ "$ENABLE_DECEPTICON" = "1" ]; then \
      pip3 install --no-cache-dir -r /tmp/requirements-decepticon.txt; \
    fi

RUN if [ "$ENABLE_SHANNON" = "1" ]; then \
      pip3 install --no-cache-dir --only-binary=lxml "lxml>=5.3.0" \
      && pip3 install --no-cache-dir -r /tmp/requirements-shannon-llm.txt; \
    fi

RUN if [ "$ENABLE_ZYPHERON" = "1" ]; then \
      pip3 install --no-cache-dir -r /tmp/requirements-zypheron-base.txt; \
    fi

RUN if [ "$ENABLE_ZYPHERON_ML" = "1" ]; then \
      pip3 install --no-cache-dir -r /tmp/requirements-zypheron-ml.txt; \
    fi

RUN if [ "$ENABLE_ML" = "1" ]; then \
      apt-get update && apt-get install -y \
        gfortran libopenblas-dev liblapack-dev libgomp1 \
      && rm -rf /var/lib/apt/lists/* \
      && pip3 install --no-cache-dir -r /tmp/requirements-zypheron-ml.txt; \
    fi

RUN if [ "$ENABLE_PLAYWRIGHT" = "1" ]; then \
      pip3 install --no-cache-dir \
        -r /tmp/requirements-zypheron-web.txt \
        -r /tmp/requirements-shannon-playwright.txt \
      && playwright install --with-deps; \
    fi

ENV PATH="/usr/local/go/bin:/root/go/bin:$PATH"

# ── Go-based security tools ───────────────────────────────────────────────────
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install -v github.com/owasp-amass/amass/v4/...@latest \
 && ln -sf /root/go/bin/subfinder /usr/bin/subfinder \
 && ln -sf /root/go/bin/nuclei /usr/bin/nuclei \
 && ln -sf /root/go/bin/dnsx /usr/bin/dnsx \
 && ln -sf /root/go/bin/amass /usr/bin/amass

# ── Zypheron Go CLI ───────────────────────────────────────────────────────────
COPY tools/zypheron/zypheron-go /app/tools/zypheron/zypheron-go
RUN cd /app/tools/zypheron/zypheron-go && go mod tidy && go build -o /usr/local/bin/zypheron ./cmd/zypheron

# ── Zypheron Python AI engine ─────────────────────────────────────────────────
RUN pip3 install --no-cache-dir -e /app/tools/zypheron/zypheron-ai || true

RUN if [ "$ENABLE_SECURITY" = "1" ]; then \
      pip3 install --no-cache-dir -r /tmp/requirements-zypheron-security.txt; \
    fi

COPY chimera/chimera-core /app/chimera-core
