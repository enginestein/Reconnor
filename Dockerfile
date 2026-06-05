FROM python:3.11-slim

LABEL description="Reconnor - Educational Hacking & OSINT Suite"

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    netcat-openbsd \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python3 -c "from tools import TOOLS; print(f'Loaded {len(TOOLS)} tools')"

ENTRYPOINT ["python3", "main.py"]
CMD []
