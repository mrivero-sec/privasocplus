# Build context: the repository root (privasoc+ is a uv workspace, one lock at the root).
#   docker build -f packages/privasoc/Dockerfile .
FROM python:3.12-slim
RUN pip install --no-cache-dir uv==0.12.13
# Vector's VRL runtime is the parser sandbox (D9)
COPY --from=timberio/vector:0.55.0-debian /usr/bin/vector /usr/local/bin/vector
WORKDIR /app
# Workspace lock and member manifests; only privasoc is installed.
COPY pyproject.toml uv.lock ./
COPY packages/gateway/pyproject.toml packages/gateway/README.md packages/gateway/
COPY packages/privasoc/pyproject.toml packages/privasoc/README.md packages/privasoc/
COPY packages/privasoc/src packages/privasoc/src
RUN uv sync --frozen --no-dev --package privasoc --no-editable \
    && useradd --uid 1000 --create-home privasoc
ENV PATH=/app/.venv/bin:$PATH PRIVASOC_HOST=0.0.0.0 PRIVASOC_DATA_DIR=/data
USER privasoc
EXPOSE 8000
CMD ["privasoc", "serve"]
