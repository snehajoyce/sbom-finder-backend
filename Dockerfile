FROM python:3.12-slim

WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy rest of the application
COPY . .

# Create necessary directories
RUN mkdir -p sbom_files/SBOM uploads

# The Cloud Run container runs with a non-root user by default
# We need to grant permissions to our working directories
RUN chmod -R 777 sbom_files uploads instance

# Port is specified by the PORT environment variable in Cloud Run
ENV PORT=8080

# Run application with Gunicorn
CMD exec gunicorn --bind :$PORT app:app
