FROM python:3.10-slim

LABEL maintainer="Adarian Dewberry <hello@adariandewberry.ai>"
LABEL description="🐕 Frankie - AI Security Code Review Agent for Homelabs"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install frankie CLI
RUN pip install --no-cache-dir -e .

# Expose Gradio port for web UI
EXPOSE 7860

# Default to web UI
ENV GRADIO_SERVER_NAME=0.0.0.0
ENV GRADIO_SERVER_PORT=7860

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:7860/info || exit 1

# Run app.py by default (Gradio web UI)
CMD ["python", "app.py"]
