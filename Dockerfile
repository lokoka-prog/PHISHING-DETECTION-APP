# Base image with lightweight Python environment
FROM python:3.10-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set workspace directory inside container
WORKDIR /app

# Install OS dependencies (e.g., SQLite3, build tools, curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    sqlite3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency definition and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy remaining application source code, config files, and ML artifacts
COPY . .

# Expose Streamlit's default port
EXPOSE 8501

# Healthcheck to monitor app status
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Command to launch Streamlit app on container boot
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]