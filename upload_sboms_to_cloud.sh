#!/bin/bash
# This script uploads SBOM files from local folders to the Cloud Storage bucket

# Set variables
PROJECT_ID="scenic-block-458718-t0"
BUCKET_NAME="sbom-finder-storage"

echo "Checking gcloud authentication..."
# Check if logged in
if ! gcloud auth print-access-token &>/dev/null; then
    echo "Not authenticated with gcloud. Please run: gcloud auth login"
    exit 1
fi

# Ensure correct project is set
gcloud config set project $PROJECT_ID

echo "Uploading SBOM files to Cloud Storage bucket gs://$BUCKET_NAME"

# Upload files from sbom_files directory
if [ -d "sbom_files" ]; then
    echo "Uploading files from sbom_files directory..."
    # Use find with -print0 and xargs for better handling of filenames with spaces
    find sbom_files -type f -name "*.json" -print0 | xargs -0 -I{} bash -c '
        file="$1"
        echo "Uploading $file to gs://'"$BUCKET_NAME"'/$file"
        gsutil -q cp "$file" "gs://'"$BUCKET_NAME"'/$file"
    ' _ {}
    
    # Upload files from SBOM dataset directory if it exists
    if [ -d "sbom_files/SBOM" ]; then
        echo "Uploading files from sbom_files/SBOM directory..."
        find sbom_files/SBOM -type f -name "*.json" -print0 | xargs -0 -I{} bash -c '
            file="$1"
            echo "Uploading $file to gs://'"$BUCKET_NAME"'/$file"
            gsutil -q cp "$file" "gs://'"$BUCKET_NAME"'/$file"
        ' _ {}
    fi
    echo "SBOM files uploaded successfully"
else
    echo "No sbom_files directory found."
    exit 1
fi 