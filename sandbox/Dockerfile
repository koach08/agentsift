FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    strace \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

COPY runner.py /opt/agentsift/runner.py

RUN useradd --create-home --shell /bin/bash sandboxuser
USER sandboxuser

WORKDIR /workspace
