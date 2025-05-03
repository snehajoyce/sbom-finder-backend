#!/bin/bash
set -e

# Set variables
PROJECT_ID=$(gcloud config get-value project)
SERVICE_NAME="sbom-finder"
REGION="us-central1"
BUCKET_NAME="sbom-finder-storage"

# Check if project ID is set
if [ -z "$PROJECT_ID" ]; then
    echo "Error: No project ID set. Run 'gcloud config set project YOUR_PROJECT_ID'"
    exit 1
fi

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
touch empty.txt
gsutil cp empty.txt gs://$BUCKET_NAME/sbom_files/
gsutil cp empty.txt gs://$BUCKET_NAME/sbom_files/SBOM/
gsutil cp empty.txt gs://$BUCKET_NAME/uploads/
rm empty.txt

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
    --service-account="$SERVICE_NAME-sa@$PROJECT_ID.iam.gserviceaccount.com"

echo "Deployment completed! Your service URL is:"
gcloud run services describe $SERVICE_NAME --platform managed --region $REGION --format="value(status.url)" 