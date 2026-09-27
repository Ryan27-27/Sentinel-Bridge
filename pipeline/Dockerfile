# AppSec Pipeline Sentinel — multi-stage Docker build

# Stage 1: build ffuf from source (keeps final image lean — no Go toolchain in the runtime image)
FROM golang:1.26-alpine AS ffuf-builder
RUN apk add --no-cache git
RUN go install github.com/ffuf/ffuf/v2@latest

FROM python:3.11-slim AS base

LABEL maintainer="Aryan Adityaa"
LABEL description="AppSec Pipeline Sentinel - SSDLC Security Automation Platform"

# Create non-root user (security best practice)
RUN groupadd -r sentinel && useradd -r -g sentinel sentinel

WORKDIR /app

# Bring in the ffuf binary built in the previous stage
COPY --from=ffuf-builder /go/bin/ffuf /usr/local/bin/ffuf

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Ensure the non-root user owns the app dir (DB file gets written here)
RUN chown -R sentinel:sentinel /app

USER sentinel

ENTRYPOINT ["python3", "sentinel.py"]
CMD ["status"]
