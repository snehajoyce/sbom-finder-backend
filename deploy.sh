#!/bin/bash
set -e

# Project ID
PROJECT_ID=scenic-block-458718-t0

# Pull the latest image
docker pull gcr.io/$PROJECT_ID/sbom-finder:sbom-server-us-east4-latest || {
  echo "Image not found, trying initial image..."
  docker pull gcr.io/$PROJECT_ID/sbom-finder:sbom-server-us-east4-initial || {
    echo "No Docker images found. You need to build and push an image first."
    echo "Run: docker build -t gcr.io/$PROJECT_ID/sbom-finder:sbom-server-us-east4-initial ."
    echo "And: docker push gcr.io/$PROJECT_ID/sbom-finder:sbom-server-us-east4-initial"
    exit 1
  }
}

# Stop and remove the existing container
docker stop sbom-finder || true
docker rm sbom-finder || true

# Ensure directories exist 
mkdir -p /mnt/sbom-data/sbom_files
mkdir -p /mnt/sbom-data/uploads
mkdir -p /mnt/sbom-data/sbom_files/SBOM
chmod -R 777 /mnt/sbom-data

# Run the new container with volumes mounted
echo "Starting the container..."
docker run -d \
  --name sbom-finder \
  -p 80:8080 \
  -v /mnt/sbom-data:/data \
  -v /mnt/sbom-data/sbom_files:/app/sbom_files \
  -v /mnt/sbom-data/uploads:/app/uploads \
  -e SQLITE_PATH=/data/sboms.db \
  --restart unless-stopped \
  gcr.io/$PROJECT_ID/sbom-finder:sbom-server-us-east4-latest || \
  docker run -d \
    --name sbom-finder \
    -p 80:8080 \
    -v /mnt/sbom-data:/data \
    -v /mnt/sbom-data/sbom_files:/app/sbom_files \
    -v /mnt/sbom-data/uploads:/app/uploads \
    -e SQLITE_PATH=/data/sboms.db \
    --restart unless-stopped \
    gcr.io/$PROJECT_ID/sbom-finder:sbom-server-us-east4-initial

# Initialize database if it doesn't exist
if [ ! -f /mnt/sbom-data/sboms.db ]; then
  echo "Initializing database..."
  docker exec sbom-finder python -c "from app import db; db.create_all()"
fi

# Verify container is running
docker ps | grep sbom-finder
echo "Deployment completed successfully!" 