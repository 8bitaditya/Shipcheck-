FROM python:3.11-slim

WORKDIR /app

# Install system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency specifications and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and tests
# (pyproject.toml declares README.md as the package readme, so it must be present)
COPY pyproject.toml README.md ./
COPY src/ /app/src/
COPY tests/ /app/tests/
# Recorded real scan replayed by GET /api/demo (no live calls during judging)
COPY golden/ /app/golden/
# the only target a live demo scan may run (fixed, never caller input)
COPY fixtures/ /app/fixtures/

# Install package in editable mode
RUN pip install --no-cache-dir -e .

# --build-arg PUBLIC_DEMO=1 for a public URL: disables POST /scan (see config.PUBLIC_DEMO)
ARG PUBLIC_DEMO=0
ENV PYTHONUNBUFFERED=1 HOST=0.0.0.0 PORT=8000 SHIPCHECK_PUBLIC_DEMO=${PUBLIC_DEMO}
EXPOSE 8000

# Serve the ShipCheck dashboard + API (FR-8).
CMD ["uvicorn", "shipcheck.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
