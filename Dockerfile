FROM python:3.11-slim

WORKDIR /app

# System deps for network tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils whois curl nmap && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ backend/
COPY frontend/ frontend/

RUN mkdir -p data/results

EXPOSE 8444

CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8444}"]