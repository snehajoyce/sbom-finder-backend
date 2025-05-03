#!/bin/bash
# Full setup script for SBOM Finder on GCE (East Region)
set -e  # Exit on any error

# Error handling function
handle_error() {
    echo "Error occurred at line $1"
    exit 1
}

# Set up error handling
trap 'handle_error $LINENO' ERR

# Cleanup function
cleanup() {
    echo "Running cleanup..."
    # Remove temporary files
    rm -f deploy.sh startup-script.sh
    echo "Cleanup complete."
}

# Register cleanup handler
trap cleanup EXIT

# --- STEP 0: Check and install gcloud if needed ---
if ! command -v gcloud &> /dev/null
then
    echo "gcloud could not be found, installing Google Cloud SDK..."
    # Install prerequisites
    sudo apt-get update
    sudo apt-get install -y apt-transport-https ca-certificates gnupg curl
    
    # Add Google Cloud SDK distribution URI as a package source
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
    
    # Import the Google Cloud public key
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
    
    # Update and install the SDK
    sudo apt-get update
    sudo apt-get install -y google-cloud-cli
    
    # Prompt for authentication
    echo "Please authenticate with Google Cloud:"
    gcloud auth login
    
    # Prompt for project selection
    echo "Please select your Google Cloud project:"
    gcloud projects list
    echo "Enter your project ID:"
    read input_project_id
    gcloud config set project $input_project_id
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null
then
    echo "Docker could not be found, installing..."
    sudo apt-get update
    sudo apt-get install -y apt-transport-https ca-certificates curl gnupg

    # Use a temporary file instead of piping directly to avoid TTY issues
    echo "Getting Docker GPG key..."
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /tmp/docker.gpg
    sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg /tmp/docker.gpg
    rm -f /tmp/docker.gpg

    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io
    sudo usermod -aG docker $USER
    echo "Docker installed. You may need to log out and back in for group changes to take effect."
    echo "If you encounter Docker permission issues, please run: newgrp docker"
fi

# Verify gcloud authentication
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
    echo "Not authenticated with Google Cloud. Please login:"
    gcloud auth login
fi

# Function to check if input is a yes response
is_yes_response() {
    local input=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    [[ "$input" == "y" || "$input" == "yes" || "$input" == "true" || "$input" == "1" ]]
    return $?
}

# --- STEP 1: Configure GCP project and region ---
# Get current project or prompt for one
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ]; then
    echo "No project set. Please select your Google Cloud project:"
    gcloud projects list
    echo "Enter your project ID:"
    read PROJECT_ID
    gcloud config set project $PROJECT_ID
fi

# Ensure billing is enabled
BILLING_ENABLED=$(gcloud billing projects describe $PROJECT_ID --format="value(billingEnabled)" 2>/dev/null || echo "false")
if [ "$BILLING_ENABLED" != "true" ]; then
    echo "WARNING: Billing may not be enabled for this project."
    echo "Please ensure billing is set up before continuing: https://console.cloud.google.com/billing/linkedaccount?project=$PROJECT_ID"
    read -p "Continue anyway? (y/n): " continue_billing
    if ! is_yes_response "$continue_billing"; then
        echo "Setup aborted."
        exit 0
    fi
fi

# Choose region
echo "Available regions:"
echo "1) us-east4 (Northern Virginia)"
echo "2) us-central1 (Iowa)"
echo "3) us-west1 (Oregon)"
echo "4) europe-west1 (Belgium)"
echo "5) asia-east1 (Taiwan)"
read -p "Select region (1-5, default: 1): " region_choice

case $region_choice in
    2) REGION="us-central1" ;;
    3) REGION="us-west1" ;;
    4) REGION="europe-west1" ;;
    5) REGION="asia-east1" ;;
    *) REGION="us-east4" ;;
esac

ZONE=$REGION-a

# VM configuration options
read -p "Enter VM name (default: sbom-server-$REGION): " custom_vm_name
VM_NAME=${custom_vm_name:-sbom-server-$REGION}
DISK_NAME=sbom-data-disk-$VM_NAME

# VM size options
echo "Available machine types:"
echo "1) e2-small (2 vCPU, 2GB memory) - Economical"
echo "2) e2-medium (2 vCPU, 4GB memory) - Recommended"
echo "3) e2-standard-2 (2 vCPU, 8GB memory) - Performance"
echo "4) e2-standard-4 (4 vCPU, 16GB memory) - High Performance"
read -p "Select machine type (1-4, default: 2): " machine_choice

case $machine_choice in
    1) MACHINE_TYPE="e2-small" ;;
    3) MACHINE_TYPE="e2-standard-2" ;;
    4) MACHINE_TYPE="e2-standard-4" ;;
    *) MACHINE_TYPE="e2-medium" ;;
esac

# Disk size
read -p "Enter data disk size in GB (default: 10): " disk_size
DISK_SIZE=${disk_size:-10}

# Ensure the size is at least 10GB
if [ "$DISK_SIZE" -lt 10 ]; then
    echo "Minimum disk size is 10GB, setting to 10GB"
    DISK_SIZE=10
fi

echo "Setting up SBOM Finder in project: $PROJECT_ID, zone: $ZONE"
echo "VM Name: $VM_NAME"
echo "Machine Type: $MACHINE_TYPE"
echo "Data Disk Size: ${DISK_SIZE}GB"
read -p "Continue with setup? (y/n, default: y): " continue_setup
if [[ -n "$continue_setup" ]] && ! is_yes_response "$continue_setup"; then
    echo "Setup aborted."
    exit 0
fi

# --- STEP 2: Enable required GCP APIs ---
echo "Enabling required APIs..."
gcloud services enable compute.googleapis.com \
  containerregistry.googleapis.com \
  cloudbuild.googleapis.com \
  iam.googleapis.com || {
      echo "Failed to enable APIs. Please check your permissions and billing status."
      exit 1
  }

# --- STEP 3: Create persistent disk in region ---
echo "Creating persistent disk: $DISK_NAME..."
# Check if the disk already exists using list
if gcloud compute disks list --filter="name=$DISK_NAME" --zones=$ZONE --format="value(name)" | grep -qx "$DISK_NAME"; then
    echo "Disk $DISK_NAME already exists, skipping creation."
else
    echo "Disk $DISK_NAME does not exist, creating..."
    if ! gcloud compute disks create $DISK_NAME \
        --size=${DISK_SIZE}GB \
        --type=pd-balanced \
        --zone=$ZONE; then
        echo "Failed to create disk. Please check your permissions and quotas."
        exit 1
    fi
fi

# --- STEP 4: Create VM with disk attached in region ---
echo "Creating VM: $VM_NAME..."
# Check if the VM already exists
if gcloud compute instances describe $VM_NAME --zone=$ZONE &>/dev/null; then
    echo "VM $VM_NAME already exists, skipping creation."
else
    gcloud compute instances create $VM_NAME \
        --zone=$ZONE \
        --machine-type=$MACHINE_TYPE \
        --create-disk=boot=yes,auto-delete=yes,size=20,type=pd-standard,image-project=debian-cloud,image-family=debian-12 \
        --disk=name=$DISK_NAME,device-name=sbom-data-disk,mode=rw,boot=no \
        --tags=http-server,https-server \
        --scopes=storage-full,compute-rw,logging-write || {
            echo "Failed to create VM. Please check your permissions and quotas."
            # Don't delete the disk if it existed before
            if ! gcloud compute disks describe $DISK_NAME --zone=$ZONE &>/dev/null; then
                gcloud compute disks delete $DISK_NAME --zone=$ZONE --quiet
            fi
            exit 1
        }
fi

# Create a startup script to handle automatic mounting on reboot
echo "Creating startup script for automatic mounting..."
cat > startup-script.sh << 'EOF'
#!/bin/bash
# Mount disk if not already mounted
if ! grep -qs '/mnt/sbom-data' /proc/mounts; then
  mkdir -p /mnt/sbom-data
  mount -o discard,defaults /dev/disk/by-id/google-sbom-data-disk /mnt/sbom-data
  chmod 777 /mnt/sbom-data
fi
EOF

gcloud compute instances add-metadata $VM_NAME \
    --zone=$ZONE \
    --metadata-from-file startup-script=startup-script.sh

# --- STEP 5: Create firewall rule for HTTP/HTTPS traffic ---
echo "Creating firewall rules..."
FIREWALL_NAME="allow-http-$VM_NAME"
# Check if firewall rule already exists
if gcloud compute firewall-rules describe $FIREWALL_NAME &>/dev/null; then
    echo "Firewall rule $FIREWALL_NAME already exists, skipping creation."
else
    gcloud compute firewall-rules create $FIREWALL_NAME \
        --allow=tcp:80,tcp:443 \
        --target-tags=http-server,https-server \
        --description="Allow HTTP and HTTPS traffic for $VM_NAME"
fi

# --- STEP 6: Wait for VM to be ready ---
echo "Waiting for VM to be ready..."
sleep 30

# Function to check VM status
check_vm_status() {
    local max_retries=10
    local retry_count=0
    
    while [ $retry_count -lt $max_retries ]; do
        if gcloud compute ssh $VM_NAME --zone=$ZONE --command="echo VM is ready" --quiet &>/dev/null; then
            return 0
        fi
        echo "VM not ready yet, waiting... (attempt $((retry_count+1))/$max_retries)"
        sleep 15
        retry_count=$((retry_count+1))
    done
    
    echo "Could not connect to VM after $max_retries attempts"
    return 1
}

echo "Checking VM connection..."
if ! check_vm_status; then
    echo "Failed to connect to VM. Check the VM status in the GCP console."
    echo "You may need to continue setup manually."
    exit 1
fi

# --- STEP 7: Set up the VM and disk ---
echo "Setting up VM environment..."
gcloud compute ssh $VM_NAME --zone=$ZONE -- "bash -s" << 'EOF'
# Disable strict error handling during disk setup
set +e

echo "Checking disk status..."
# First make sure the disk isn't mounted
if grep -q "/dev/disk/by-id/google-sbom-data-disk" /proc/mounts; then
    echo "Disk is currently mounted, unmounting first..."
    sudo umount -f /dev/disk/by-id/google-sbom-data-disk || {
        echo "Failed to unmount disk. Trying alternative approaches..."
        # Find mount point
        MOUNT_POINT=$(grep "/dev/disk/by-id/google-sbom-data-disk" /proc/mounts | awk '{print $2}')
        if [ -n "$MOUNT_POINT" ]; then
            echo "Trying to unmount from $MOUNT_POINT"
            sudo umount -f $MOUNT_POINT || echo "Warning: Could not unmount from $MOUNT_POINT"
        fi
    }
    # Double-check if unmounted
    if grep -q "/dev/disk/by-id/google-sbom-data-disk" /proc/mounts; then
        echo "WARNING: Disk still mounted, processes may be using it"
        # List processes using the mount
        sudo lsof | grep "$MOUNT_POINT" || echo "No processes found using the mount"
    else
        echo "Disk successfully unmounted"
    fi
else
    echo "Disk is not currently mounted"
fi

# Check if disk exists and is visible
if [ -e "/dev/disk/by-id/google-sbom-data-disk" ]; then
    echo "Disk device exists"
    # Check if disk is already formatted
    if sudo blkid /dev/disk/by-id/google-sbom-data-disk | grep -q 'TYPE="ext4"'; then
        echo "Disk is already formatted as ext4"
    else
        echo "Formatting disk as ext4..."
        # Force format the disk
        sudo mkfs.ext4 -F -m 0 -E lazy_itable_init=0,lazy_journal_init=0,discard /dev/disk/by-id/google-sbom-data-disk
        if [ $? -ne 0 ]; then
            echo "WARNING: Formatting failed, checking device status..."
            sudo lsblk -f
        else
            echo "Disk formatted successfully"
        fi
    fi
    
    # Create mount point and mount
    echo "Setting up mount point..."
    sudo mkdir -p /mnt/sbom-data
    
    # Mount the disk
    echo "Mounting disk..."
    sudo mount -o discard,defaults /dev/disk/by-id/google-sbom-data-disk /mnt/sbom-data
    if [ $? -ne 0 ]; then
        echo "Mount failed, checking device and mount status..."
        echo "Device status:"
        sudo lsblk -f
        echo "Current mounts:"
        cat /proc/mounts | grep "/dev/disk/by-id/google-sbom-data-disk" || echo "Disk not mounted"
    else
        echo "Disk mounted successfully"
    fi
    
    # Set permissions
    sudo chmod 777 /mnt/sbom-data
else
    echo "ERROR: Disk device /dev/disk/by-id/google-sbom-data-disk not found!"
    echo "Available disks:"
    ls -la /dev/disk/by-id/ || echo "No disks found in /dev/disk/by-id/"
    echo "Block devices:"
    sudo lsblk
    exit 1
fi

# Re-enable strict error handling for the rest of the script
set -e

# Add disk to /etc/fstab to persist across reboots
echo "Setting up persistent mount..."
grep -qxF '/dev/disk/by-id/google-sbom-data-disk /mnt/sbom-data ext4 discard,defaults,nofail 0 2' /etc/fstab \
  || echo '/dev/disk/by-id/google-sbom-data-disk /mnt/sbom-data ext4 discard,defaults,nofail 0 2' | sudo tee -a /etc/fstab

# Install Docker
echo "Installing Docker..."
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg

# Use a temporary file instead of piping directly to avoid TTY issues
echo "Getting Docker GPG key..."
curl -fsSL https://download.docker.com/linux/debian/gpg -o /tmp/docker.gpg
sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg /tmp/docker.gpg
rm -f /tmp/docker.gpg

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
# Create a shorter service account name that fits within the 30-character limit
VM_SHORT_NAME=$(echo $VM_NAME | sed 's/sbom-server-/sbom-/')
SERVICE_ACCOUNT_NAME="gh-action-$VM_SHORT_NAME"

# Ensure the service account name is less than 30 characters
if [ ${#SERVICE_ACCOUNT_NAME} -gt 30 ]; then
    # Truncate to ensure it's under 30 characters
    SERVICE_ACCOUNT_NAME="${SERVICE_ACCOUNT_NAME:0:27}-sa"
    echo "Service account name truncated to $SERVICE_ACCOUNT_NAME to meet length requirements"
fi

SERVICE_ACCOUNT_ID="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# Check if service account already exists
if gcloud iam service-accounts describe $SERVICE_ACCOUNT_ID &>/dev/null; then
    echo "Service account $SERVICE_ACCOUNT_ID already exists"
else
    gcloud iam service-accounts create $SERVICE_ACCOUNT_NAME \
        --display-name="GitHub Actions Deployer for $VM_NAME"
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

# Create GitHub Actions workflow file with specific VM name
cat > .github/workflows/deploy-to-$VM_NAME.yml << EOF
name: Build and Deploy to $VM_NAME

on:
  push:
    branches:
      - main  # or master, depending on your default branch

jobs:
  build-and-deploy:
    name: Build and Deploy to $REGION
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Set up Cloud SDK
      uses: google-github-actions/setup-gcloud@v1
      with:
        project_id: \${{ secrets.GCP_PROJECT_ID }}
        service_account_key: \${{ secrets.GCP_SA_KEY }}
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
        
        docker build -t gcr.io/\${{ secrets.GCP_PROJECT_ID }}/sbom-finder:$VM_NAME-\${{ github.sha }} .
        docker tag gcr.io/\${{ secrets.GCP_PROJECT_ID }}/sbom-finder:$VM_NAME-\${{ github.sha }} gcr.io/\${{ secrets.GCP_PROJECT_ID }}/sbom-finder:$VM_NAME-latest

    # Push the Docker image to Google Container Registry
    - name: Push Docker image to GCR
      run: |
        docker push gcr.io/\${{ secrets.GCP_PROJECT_ID }}/sbom-finder:$VM_NAME-\${{ github.sha }}
        docker push gcr.io/\${{ secrets.GCP_PROJECT_ID }}/sbom-finder:$VM_NAME-latest

    # Create the deploy script that will run on the VM
    - name: Create deploy script
      run: |
        cat > deploy.sh << 'DEPLOYEOF'
#!/bin/bash
set -e

# Pull the latest image
docker pull gcr.io/\$PROJECT_ID/sbom-finder:$VM_NAME-latest

# Stop and remove the existing container
docker stop sbom-finder || true
docker rm sbom-finder || true

# Ensure directories exist 
mkdir -p /mnt/sbom-data/sbom_files
mkdir -p /mnt/sbom-data/uploads
mkdir -p /mnt/sbom-data/sbom_files/SBOM
chmod -R 777 /mnt/sbom-data

# Run the new container with volumes mounted
docker run -d \\
  --name sbom-finder \\
  -p 80:8080 \\
  -v /mnt/sbom-data:/data \\
  -v /mnt/sbom-data/sbom_files:/app/sbom_files \\
  -v /mnt/sbom-data/uploads:/app/uploads \\
  -e SQLITE_PATH=/data/sboms.db \\
  --restart unless-stopped \\
  gcr.io/\$PROJECT_ID/sbom-finder:$VM_NAME-latest

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
        gcloud compute scp deploy.sh $VM_NAME:~ --zone=$ZONE
        
        # Execute deploy script on VM
        gcloud compute ssh $VM_NAME --zone=$ZONE -- \\
          "PROJECT_ID=\${{ secrets.GCP_PROJECT_ID }} bash ~/deploy.sh"
      
    # Get deployed application URL
    - name: Get Application URL
      run: |
        VM_IP=\$(gcloud compute instances describe $VM_NAME --zone=$ZONE --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
        echo "::set-output name=app_url::http://\$VM_IP/"
        echo "Application deployed to: http://\$VM_IP/"
EOF

# Create Dockerfile if it doesn't exist
if [ ! -f Dockerfile ]; then
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
    echo "Dockerfile created!"
fi

echo "Local repository files created!"

# --- STEP 10: Update app.py to use environment variable ---
# Check if app.py exists and modify it
if [ -f app.py ]; then
    echo "Updating app.py to use environment variable..."
    # Create backup of app.py
    cp app.py app.py.bak
    
    # Check if app.py already has the modification
    if grep -q "SQLITE_PATH = os.environ.get('SQLITE_PATH'" app.py; then
        echo "app.py already updated to use environment variable, skipping."
    else
        # Update app.py to use SQLITE_PATH environment variable
        sed -i 's#app.config\['\''SQLALCHEMY_DATABASE_URI'\''\] = '\''sqlite:///sboms.db'\''#SQLITE_PATH = os.environ.get('\''SQLITE_PATH'\'', '\''sboms.db'\'')\napp.config['\''SQLALCHEMY_DATABASE_URI'\''] = f'\''sqlite:///{SQLITE_PATH}'\''#' app.py
        echo "app.py updated!"
    fi
else
    echo "Warning: app.py not found, skipping modification"
fi

# --- STEP 11: Build and push initial Docker image ---
echo "Building and pushing initial Docker image..."

# Check if Docker is available in this session
if ! docker info &>/dev/null; then
    echo "Warning: Docker may not be available in this session."
    echo "You'll need to build and push the image later with these commands:"
    echo "docker build -t gcr.io/$PROJECT_ID/sbom-finder:$VM_NAME-initial ."
    echo "docker push gcr.io/$PROJECT_ID/sbom-finder:$VM_NAME-initial"
    SKIP_DOCKER=true
else
    SKIP_DOCKER=false
fi

if [ "$SKIP_DOCKER" = false ]; then
    # Build and push the Docker image
    docker build -t gcr.io/$PROJECT_ID/sbom-finder:$VM_NAME-initial .
    docker push gcr.io/$PROJECT_ID/sbom-finder:$VM_NAME-initial || {
        echo "Failed to push Docker image. You may need to configure Docker with:"
        echo "gcloud auth configure-docker"
        echo "Then retry manually with:"
        echo "docker build -t gcr.io/$PROJECT_ID/sbom-finder:$VM_NAME-initial ."
        echo "docker push gcr.io/$PROJECT_ID/sbom-finder:$VM_NAME-initial"
        SKIP_DOCKER=true
    }
fi

# --- STEP 12: Initial deployment to VM ---
echo "Preparing initial deployment to VM..."

# Create deploy script
cat > deploy.sh << EOF
#!/bin/bash
set -e

# Pull the latest image
docker pull gcr.io/$PROJECT_ID/sbom-finder:$VM_NAME-initial

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
  gcr.io/$PROJECT_ID/sbom-finder:$VM_NAME-initial

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

if [ "$SKIP_DOCKER" = false ]; then
    # Copy and execute deployment script on VM
    echo "Deploying to VM..."
    gcloud compute scp deploy.sh $VM_NAME:~ --zone=$ZONE
    gcloud compute ssh $VM_NAME --zone=$ZONE -- "PROJECT_ID=$PROJECT_ID bash ~/deploy.sh"
else
    echo "Skipping deployment since Docker image wasn't built."
    echo "To deploy later, run:"
    echo "gcloud compute scp deploy.sh $VM_NAME:~ --zone=$ZONE"
    echo "gcloud compute ssh $VM_NAME --zone=$ZONE -- \"PROJECT_ID=$PROJECT_ID bash ~/deploy.sh\""
fi

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
echo "2. Push your code to GitHub with the .github/workflows/deploy-to-$VM_NAME.yml file"
echo "   Future pushes to your main branch will trigger automatic deployments"
echo ""
echo "3. Monitor your VM at: https://console.cloud.google.com/compute/instancesDetail/zones/$ZONE/instances/$VM_NAME?project=$PROJECT_ID"
echo ""
echo "Don't forget to securely store the service account key: $KEY_FILE"
echo "Keep it secure and don't add it to your Git repository."

# Make the setup script executable again if needed
chmod +x "$0"
