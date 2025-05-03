#!/bin/bash
# Full setup script for SBOM Finder on GCE (East Region)
set -e  # Exit on any error

# --- STEP 1: Configure GCP project and region ---
# Replace these variables with your values
PROJECT_ID=$(gcloud config get-value project)
REGION=us-east4
ZONE=$REGION-a
VM_NAME=sbom-server-east
DISK_NAME=sbom-data-disk-east

echo "Setting up SBOM Finder in project: $PROJECT_ID, zone: $ZONE"

# --- STEP 2: Enable required GCP APIs ---
echo "Enabling required APIs..."
gcloud services enable compute.googleapis.com \
  containerregistry.googleapis.com \
  cloudbuild.googleapis.com \
  iam.googleapis.com

# --- STEP 3: Create persistent disk in East region ---
echo "Creating persistent disk: $DISK_NAME..."
gcloud compute disks create $DISK_NAME \
    --size=10GB \
    --type=pd-balanced \
    --zone=$ZONE

# --- STEP 4: Create VM with disk attached in East region ---
echo "Creating VM: $VM_NAME..."
gcloud compute instances create $VM_NAME \
    --zone=$ZONE \
    --machine-type=e2-medium \
    --disk=boot=yes,auto-delete=yes,size=20,type=pd-standard,image-project=debian-cloud,image-family=debian-12 \
    --disk=name=$DISK_NAME,device-name=sbom-data-disk,mode=rw,boot=no \
    --tags=http-server,https-server \
    --scopes=storage-full,compute-rw,logging-write

# --- STEP 5: Create firewall rule for HTTP/HTTPS traffic ---
echo "Creating firewall rules..."
gcloud compute firewall-rules create allow-http-east \
    --allow=tcp:80,tcp:443 \
    --target-tags=http-server,https-server \
    --description="Allow HTTP and HTTPS traffic"

# --- STEP 6: Wait for VM to be ready ---
echo "Waiting for VM to be ready..."
sleep 30

# --- STEP 7: Set up the VM and disk ---
echo "Setting up VM environment..."
gcloud compute ssh $VM_NAME --zone=$ZONE -- "bash -s" << 'EOF'
set -e

# Format and mount data disk
echo "Formatting and mounting disk..."
sudo mkfs.ext4 -m 0 -E lazy_itable_init=0,lazy_journal_init=0,discard /dev/disk/by-id/google-sbom-data-disk
sudo mkdir -p /mnt/sbom-data
sudo mount -o discard,defaults /dev/disk/by-id/google-sbom-data-disk /mnt/sbom-data
sudo chmod 777 /mnt/sbom-data

# Add disk to /etc/fstab to persist across reboots
echo "Setting up persistent mount..."
echo "/dev/disk/by-id/google-sbom-data-disk /mnt/sbom-data ext4 discard,defaults,nofail 0 2" | sudo tee -a /etc/fstab

# Install Docker
echo "Installing Docker..."
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo systemctl enable docker
sudo usermod -aG docker $USER

# Configure Docker to use GCR
echo "Configuring Docker with gcloud authentication..."
sudo gcloud auth configure-docker --quiet

# Create app directories on persistent disk
echo "Creating app directories..."
sudo mkdir -p /mnt/sbom-data/sbom_files
sudo mkdir -p /mnt/sbom-data/uploads
sudo mkdir -p /mnt/sbom-data/sbom_files/SBOM
sudo chmod -R 777 /mnt/sbom-data

# Create monitoring script
echo "Setting up monitoring..."
cat > $HOME/monitor.sh << 'EOT'
#!/bin/bash

# Check if container is running
if ! docker ps | grep -q sbom-finder; then
  echo "ALERT: SBOM Finder container is not running!"
  
  # Try to restart
  docker start sbom-finder || echo "Failed to restart container"
fi

# Check disk space
DISK_USAGE=$(df -h /mnt/sbom-data | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 85 ]; then
  echo "ALERT: Disk usage is high: $DISK_USAGE%"
fi
EOT

chmod +x $HOME/monitor.sh

# Add to crontab to run every 15 minutes
(crontab -l 2>/dev/null; echo "*/15 * * * * $HOME/monitor.sh >> $HOME/monitor.log 2>&1") | crontab -

# Setup automatic security updates
echo "Setting up automatic security updates..."
sudo apt-get install -y unattended-upgrades
sudo dpkg-reconfigure -f noninteractive unattended-upgrades

echo "VM setup complete!"
EOF

# --- STEP 8: Create a service account for GitHub Actions ---
echo "Creating service account for CI/CD..."
SERVICE_ACCOUNT_NAME="github-actions-east"
SERVICE_ACCOUNT_ID="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# Check if service account already exists
if gcloud iam service-accounts describe $SERVICE_ACCOUNT_ID &>/dev/null; then
    echo "Service account $SERVICE_ACCOUNT_ID already exists"
else
    gcloud iam service-accounts create $SERVICE_ACCOUNT_NAME \
        --display-name="GitHub Actions East Deployer"
fi

# Assign roles to the service account
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT_ID" \
    --role="roles/compute.admin"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT_ID" \
    --role="roles/storage.admin"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT_ID" \
    --role="roles/iam.serviceAccountUser"

# Create a key for the service account
KEY_FILE="$SERVICE_ACCOUNT_NAME-key.json"
gcloud iam service-accounts keys create $KEY_FILE \
    --iam-account=$SERVICE_ACCOUNT_ID

echo "Service account key created: $KEY_FILE"
echo "Base64 encoded key for GitHub secrets:"
cat $KEY_FILE | base64

# --- STEP 9: Prepare local repository files ---
echo "Setting up local repository files..."

# Create GitHub Actions workflow directory if it doesn't exist
mkdir -p .github/workflows

# Create GitHub Actions workflow file
cat > .github/workflows/deploy-east.yml << 'EOF'
name: Build and Deploy to GCE East

on:
  push:
    branches:
      - main  # or master, depending on your default branch

jobs:
  build-and-deploy:
    name: Build and Deploy to East Region
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Set up Cloud SDK
      uses: google-github-actions/setup-gcloud@v1
      with:
        project_id: ${{ secrets.GCP_PROJECT_ID }}
        service_account_key: ${{ secrets.GCP_SA_KEY }}
        export_default_credentials: true

    # Configure Docker to use the gcloud command-line tool as a credential helper
    - name: Configure Docker for GCR
      run: |
        gcloud auth configure-docker
        
    # Build the Docker image and tag with GCR path
    - name: Build Docker image
      run: |
        # Create Dockerfile if not exists
        if [ ! -f Dockerfile ]; then
          cat > Dockerfile << 'DOCKEREOF'
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .
ENV PORT=8080
EXPOSE 8080

# Set database URI to mounted directory
ENV SQLITE_PATH=/data/sboms.db

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
DOCKEREOF
        fi
        
        docker build -t gcr.io/${{ secrets.GCP_PROJECT_ID }}/sbom-finder:${{ github.sha }} .
        docker tag gcr.io/${{ secrets.GCP_PROJECT_ID }}/sbom-finder:${{ github.sha }} gcr.io/${{ secrets.GCP_PROJECT_ID }}/sbom-finder:latest

    # Push the Docker image to Google Container Registry
    - name: Push Docker image to GCR
      run: |
        docker push gcr.io/${{ secrets.GCP_PROJECT_ID }}/sbom-finder:${{ github.sha }}
        docker push gcr.io/${{ secrets.GCP_PROJECT_ID }}/sbom-finder:latest

    # Create the deploy script that will run on the VM
    - name: Create deploy script
      run: |
        cat > deploy.sh << 'DEPLOYEOF'
#!/bin/bash
set -e

# Pull the latest image
docker pull gcr.io/$PROJECT_ID/sbom-finder:latest

# Stop and remove the existing container
docker stop sbom-finder || true
docker rm sbom-finder || true

# Ensure directories exist 
mkdir -p /mnt/sbom-data/sbom_files
mkdir -p /mnt/sbom-data/uploads
mkdir -p /mnt/sbom-data/sbom_files/SBOM
chmod -R 777 /mnt/sbom-data

# Run the new container with volumes mounted
docker run -d \
  --name sbom-finder \
  -p 80:8080 \
  -v /mnt/sbom-data:/data \
  -v /mnt/sbom-data/sbom_files:/app/sbom_files \
  -v /mnt/sbom-data/uploads:/app/uploads \
  -e SQLITE_PATH=/data/sboms.db \
  --restart unless-stopped \
  gcr.io/$PROJECT_ID/sbom-finder:latest

# Initialize database if it doesn't exist
if [ ! -f /mnt/sbom-data/sboms.db ]; then
  echo "Initializing database..."
  docker exec sbom-finder python -c "from app import db; db.create_all()"
fi

# Verify container is running
docker ps | grep sbom-finder
echo "Deployment completed successfully!"
DEPLOYEOF
        
        chmod +x deploy.sh

    # Deploy to the VM using SSH
    - name: Deploy to VM
      id: deploy
      run: |
        # Add host key to known_hosts to prevent SSH prompt
        gcloud compute config-ssh
        
        # Copy deploy script to VM
        gcloud compute scp deploy.sh ${{ secrets.GCE_INSTANCE_NAME }}:~ --zone=${{ secrets.GCE_INSTANCE_ZONE }}
        
        # Execute deploy script on VM
        gcloud compute ssh ${{ secrets.GCE_INSTANCE_NAME }} --zone=${{ secrets.GCE_INSTANCE_ZONE }} -- \
          "PROJECT_ID=${{ secrets.GCP_PROJECT_ID }} bash ~/deploy.sh"
      
    # Get deployed application URL
    - name: Get Application URL
      run: |
        VM_IP=$(gcloud compute instances describe ${{ secrets.GCE_INSTANCE_NAME }} --zone=${{ secrets.GCE_INSTANCE_ZONE }} --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
        echo "::set-output name=app_url::http://$VM_IP/"
        echo "Application deployed to: http://$VM_IP/"
EOF

# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .
ENV PORT=8080
EXPOSE 8080

# Set database URI to mounted directory
ENV SQLITE_PATH=/data/sboms.db

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
EOF

echo "Local repository files created!"

# --- STEP 10: Update app.py to use environment variable ---
# Check if app.py exists and modify it
if [ -f app.py ]; then
    echo "Updating app.py to use environment variable..."
    # Create backup of app.py
    cp app.py app.py.bak
    
    # Update app.py to use SQLITE_PATH environment variable
    sed -i 's#app.config\['\''SQLALCHEMY_DATABASE_URI'\''\] = '\''sqlite:///sboms.db'\''#SQLITE_PATH = os.environ.get('\''SQLITE_PATH'\'', '\''sboms.db'\'')\napp.config['\''SQLALCHEMY_DATABASE_URI'\''] = f'\''sqlite:///{SQLITE_PATH}'\''#' app.py
    
    echo "app.py updated!"
else
    echo "Warning: app.py not found, skipping modification"
fi

# --- STEP 11: Build and push initial Docker image ---
echo "Building and pushing initial Docker image..."
docker build -t gcr.io/$PROJECT_ID/sbom-finder:initial .
docker push gcr.io/$PROJECT_ID/sbom-finder:initial

# --- STEP 12: Initial deployment to VM ---
echo "Performing initial deployment to VM..."

# Create deploy script
cat > deploy.sh << 'EOF'
#!/bin/bash
set -e

# Pull the latest image
docker pull gcr.io/$PROJECT_ID/sbom-finder:initial

# Stop and remove the existing container
docker stop sbom-finder || true
docker rm sbom-finder || true

# Ensure directories exist 
mkdir -p /mnt/sbom-data/sbom_files
mkdir -p /mnt/sbom-data/uploads
mkdir -p /mnt/sbom-data/sbom_files/SBOM
chmod -R 777 /mnt/sbom-data

# Run the new container with volumes mounted
docker run -d \
  --name sbom-finder \
  -p 80:8080 \
  -v /mnt/sbom-data:/data \
  -v /mnt/sbom-data/sbom_files:/app/sbom_files \
  -v /mnt/sbom-data/uploads:/app/uploads \
  -e SQLITE_PATH=/data/sboms.db \
  --restart unless-stopped \
  gcr.io/$PROJECT_ID/sbom-finder:initial

# Initialize database if it doesn't exist
if [ ! -f /mnt/sbom-data/sboms.db ]; then
  echo "Initializing database..."
  docker exec sbom-finder python -c "from app import db; db.create_all()"
fi

# Verify container is running
docker ps | grep sbom-finder
echo "Deployment completed successfully!"
EOF

chmod +x deploy.sh

# Copy and execute deployment script on VM
gcloud compute scp deploy.sh $VM_NAME:~ --zone=$ZONE
gcloud compute ssh $VM_NAME --zone=$ZONE -- "PROJECT_ID=$PROJECT_ID bash ~/deploy.sh"

# --- STEP 13: Display GitHub setup instructions ---
echo ""
echo "===== SETUP COMPLETE ====="
echo ""
echo "Your SBOM Finder application has been deployed to:"
VM_IP=$(gcloud compute instances describe $VM_NAME --zone=$ZONE --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
echo "http://$VM_IP/"
echo ""
echo "GitHub Actions Setup Instructions:"
echo "1. Create the following secrets in your GitHub repository:"
echo "   - GCP_PROJECT_ID: $PROJECT_ID"
echo "   - GCP_SA_KEY: <paste the base64-encoded key shown above>"
echo "   - GCE_INSTANCE_NAME: $VM_NAME"
echo "   - GCE_INSTANCE_ZONE: $ZONE"
echo ""
echo "2. Push your code to GitHub with the .github/workflows/deploy-east.yml file"
echo "   Future pushes to your main branch will trigger automatic deployments"
echo ""
echo "Don't forget to securely store the service account key: $KEY_FILE"
