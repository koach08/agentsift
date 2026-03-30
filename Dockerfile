FROM python:3.12-slim

LABEL maintainer="AgentSift Contributors"
LABEL org.opencontainers.image.source="https://github.com/koach08/agentsift"
LABEL org.opencontainers.image.description="Security scanner for AI agent plugins and MCP packages"

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir .

ENTRYPOINT ["agentsift"]
CMD ["--help"]
