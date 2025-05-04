#!/bin/bash
set -e

# Set variables
PROJECT_ID="scenic-block-458718-t0"  # Your actual project ID
SERVICE_NAME="sbom-finder"
REGION="us-central1"
BUCKET_NAME="sbom-finder-storage"

echo "Checking gcloud authentication..."
# Check if logged in
if ! gcloud auth print-access-token &>/dev/null; then
    echo "Not authenticated with gcloud. Please run: gcloud auth login"
    exit 1
fi

# Ensure correct project is set
gcloud config set project $PROJECT_ID

echo "Deploying to project: $PROJECT_ID"

# Create a Cloud Storage bucket for SBOM files if it doesn't exist
if ! gsutil ls gs://$BUCKET_NAME > /dev/null 2>&1; then
    echo "Creating Cloud Storage bucket: $BUCKET_NAME"
    gsutil mb -p $PROJECT_ID -l $REGION gs://$BUCKET_NAME
    gsutil iam ch allUsers:objectViewer gs://$BUCKET_NAME
else
    echo "Cloud Storage bucket $BUCKET_NAME already exists"
fi

# Create directories in the bucket
echo "Creating directories in the bucket"
# Create empty objects directly without using temporary files
echo "" | gsutil -q cp - gs://$BUCKET_NAME/sbom_files/empty.txt
echo "" | gsutil -q cp - gs://$BUCKET_NAME/sbom_files/SBOM/empty.txt
echo "" | gsutil -q cp - gs://$BUCKET_NAME/uploads/empty.txt

# Upload existing SBOM files to Cloud Storage
echo "Uploading existing SBOM files to Cloud Storage..."
if [ -d "sbom_files" ]; then
    # Upload files from sbom_files directory
    find sbom_files -type f -name "*.json" | while read file; do
        echo "Uploading $file to gs://$BUCKET_NAME/$file"
        gsutil cp "$file" "gs://$BUCKET_NAME/$file"
    done
    
    # Upload files from SBOM dataset directory if it exists
    if [ -d "sbom_files/SBOM" ]; then
        find sbom_files/SBOM -type f -name "*.json" | while read file; do
            echo "Uploading $file to gs://$BUCKET_NAME/$file"
            gsutil cp "$file" "gs://$BUCKET_NAME/$file"
        done
    fi
    echo "SBOM files uploaded successfully"
else
    echo "No sbom_files directory found. Skipping file upload."
fi

# Build and push the container
echo "Building and pushing container image..."
gcloud builds submit --tag gcr.io/$PROJECT_ID/$SERVICE_NAME

# Deploy to Cloud Run
echo "Deploying to Cloud Run..."
gcloud run deploy $SERVICE_NAME \
    --image gcr.io/$PROJECT_ID/$SERVICE_NAME \
    --platform managed \
    --region $REGION \
    --allow-unauthenticated \
    --memory 1Gi \
    --set-env-vars="BUCKET_NAME=$BUCKET_NAME" \
    --service-account="sbom-finder-sa@$PROJECT_ID.iam.gserviceaccount.com"

echo "Deployment completed! Your service URL is:"
gcloud run services describe $SERVICE_NAME --platform managed --region $REGION --format="value(status.url)" 