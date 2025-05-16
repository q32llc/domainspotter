FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir poetry
COPY pyproject.toml poetry.lock* ./
RUN poetry config virtualenvs.create false && \
    poetry install --without dev --no-interaction --no-ansi --no-root

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 domainspotter && \
    chown -R domainspotter:domainspotter /app

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# Switch to non-root user
USER domainspotter

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Command to run the application
CMD ["uvicorn", "domainspotter.app:app", "--host", "0.0.0.0", "--port", "8000"]
