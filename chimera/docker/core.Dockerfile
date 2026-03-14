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
    nmap masscan \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY chimera/chimera-core/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

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
COPY tools/shannon/python/llm-service/requirements.txt /tmp/requirements-shannon-llm.txt
COPY tools/shannon/python/playwright-service/requirements.txt /tmp/requirements-shannon-playwright.txt

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

RUN if [ "$ENABLE_SUBFINDER" = "1" ]; then \
      apt-get update && apt-get install -y golang-go && rm -rf /var/lib/apt/lists/* \
      && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; \
    fi

ENV PATH="/root/go/bin:$PATH"

RUN if [ "$ENABLE_SECURITY" = "1" ]; then \
      pip3 install --no-cache-dir -r /tmp/requirements-zypheron-security.txt; \
    fi

COPY chimera/chimera-core /app/chimera-core
