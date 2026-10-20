# Kali-Mind container — for authorized lab use
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    KALI_MIND_DEFAULT_PROVIDER=ollama \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    nmap masscan nikto whatweb nuclei \
    gobuster feroxbuster ffuf sqlmap \
    git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/kali-mind
COPY . /opt/kali-mind

RUN python3 -m pip install --break-system-packages -e .

# Non-root operator user
RUN useradd -m -s /bin/bash km && chown -R km:km /opt/kali-mind
USER km
WORKDIR /home/km

ENTRYPOINT ["kali-mind"]
CMD ["--help"]
