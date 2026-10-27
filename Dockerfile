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

# Install package in editable mode
RUN pip install --no-cache-dir -e .

ENV PYTHONUNBUFFERED=1

# No API exists yet, so the default command runs the test suite.
# Once shipcheck.api.main is built, switch to:
#   EXPOSE 8000
#   CMD ["uvicorn", "shipcheck.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
CMD ["python", "-m", "pytest", "-q"]
