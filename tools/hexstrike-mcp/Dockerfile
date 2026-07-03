FROM python:3.12-slim

# ── System dependencies ────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git ca-certificates gnupg unzip \
    nmap masscan \
    sqlmap \
    perl libnet-ssleay-perl libwhisker2-perl \
    dnsutils whois \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install nikto from source (not in trixie repos)
RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# ── Go toolchain (for Go-based security tools) ────────────────────────────
RUN curl -fsSL https://go.dev/dl/go1.22.3.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# ── Go-based security tools ───────────────────────────────────────────────
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true && \
    go install -v github.com/tomnomnom/waybackurls@latest 2>/dev/null || true && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true && \
    go install -v github.com/OJ/gobuster/v3@latest 2>/dev/null || true && \
    go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null || true && \
    go install -v github.com/hahwul/dalfox/v2@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || true && \
    go install -v github.com/tomnomnom/anew@latest 2>/dev/null || true

# Update nuclei templates
RUN /root/go/bin/nuclei -update-templates 2>/dev/null || true

WORKDIR /app

# ── Python dependencies ───────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Pull upstream HexStrike AI server ────────────────────────────────────
RUN curl -fsSL \
    https://raw.githubusercontent.com/0x4m4/hexstrike-ai/master/hexstrike_server.py \
    -o /app/hexstrike_upstream.py

# Patch heavy optional imports to not crash when unavailable
# angr is ~1 GB and only needed for binary analysis (not web pentesting)
RUN python3 - <<'EOF'
import re, pathlib
p = pathlib.Path("/app/hexstrike_upstream.py")
src = p.read_text()
# Wrap "import angr" in try/except
src = re.sub(
    r'^(import angr\b.*)',
    r'try:\n    \1\nexcept ImportError:\n    angr = None',
    src, flags=re.MULTILINE
)
# Wrap "from angr import ..." in try/except
src = re.sub(
    r'^(from angr import\b.*)',
    r'try:\n    \1\nexcept ImportError:\n    pass',
    src, flags=re.MULTILINE
)
p.write_text(src)
print("angr import patched")
EOF

# ── Our server files ──────────────────────────────────────────────────────
COPY server.py .
COPY hexstrike_mcp.py .
COPY launcher.py .

EXPOSE 8888

CMD ["python3", "launcher.py"]
