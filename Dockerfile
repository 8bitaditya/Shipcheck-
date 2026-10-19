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

# Copy application source code and fixtures
COPY src/ /app/src/
COPY fixtures/ /app/fixtures/
COPY golden/ /app/golden/
COPY pyproject.toml .

# Install package in editable mode
RUN pip install --no-cache-dir -e .

EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=8000

CMD ["uvicorn", "shipcheck.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
