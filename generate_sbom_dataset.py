#!/usr/bin/env python3
import os
import json
import subprocess
import shutil
import logging
import sys
import time
from datetime import datetime

# Configuration
DATASET_DIR = "./SBOM Dataset"
LOCAL_BACKUP_DIR = os.path.expanduser("~/local_sbom_backup")
WINDOWS_DIR = "/mnt/c/Users/Gunty Snehajoyce/Documents/SBOM"  # WSL path to Windows location
SBOM_FILES_DIR = "./sbom_files"
LOG_FILE = "sbom_generation.log"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Ensure directories exist
os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(LOCAL_BACKUP_DIR, exist_ok=True)
os.makedirs(SBOM_FILES_DIR, exist_ok=True)
try:
    os.makedirs(WINDOWS_DIR, exist_ok=True)
    logger.info(f"Windows directory created/verified: {WINDOWS_DIR}")
except Exception as e:
    logger.warning(f"Could not create Windows directory: {e}")

# List of common Linux applications for SBOM generation
APPLICATIONS = [
    # Browsers
    {"name": "firefox", "category": "browser", "package": "firefox"},
    {"name": "chromium", "category": "browser", "package": "chromium-browser"},
    
    # Text Editors
    {"name": "vim", "category": "editor", "package": "vim"},
    {"name": "nano", "category": "editor", "package": "nano"},
    {"name": "gedit", "category": "editor", "package": "gedit"},
    
    # Terminals
    {"name": "gnome-terminal", "category": "terminal", "package": "gnome-terminal"},
    {"name": "terminator", "category": "terminal", "package": "terminator"},
    
    # Development Tools
    {"name": "git", "category": "development", "package": "git"},
    {"name": "python3", "category": "development", "package": "python3"},
    {"name": "nodejs", "category": "development", "package": "nodejs"},
    {"name": "npm", "category": "development", "package": "npm"},
    
    # Utilities
    {"name": "curl", "category": "utility", "package": "curl"},
    {"name": "wget", "category": "utility", "package": "wget"},
    {"name": "htop", "category": "utility", "package": "htop"},
    {"name": "tmux", "category": "utility", "package": "tmux"},
    
    # Image Editors
    {"name": "gimp", "category": "graphics", "package": "gimp"},
    {"name": "inkscape", "category": "graphics", "package": "inkscape"},
    
    # Media Players
    {"name": "vlc", "category": "media", "package": "vlc"},
    {"name": "audacity", "category": "media", "package": "audacity"},
    
    # Office Applications
    {"name": "libreoffice", "category": "office", "package": "libreoffice"},
    {"name": "calibre", "category": "office", "package": "calibre"},
    
    # Network Tools
    {"name": "wireshark", "category": "network", "package": "wireshark"},
    {"name": "nmap", "category": "network", "package": "nmap"},
]

# Load custom applications from JSON if exists
CUSTOM_APPS_FILE = "custom_apps.json"
if os.path.exists(CUSTOM_APPS_FILE):
    try:
        with open(CUSTOM_APPS_FILE, 'r') as f:
            custom_apps = json.load(f)
            APPLICATIONS.extend(custom_apps)
            logger.info(f"Loaded {len(custom_apps)} custom applications from {CUSTOM_APPS_FILE}")
    except Exception as e:
        logger.error(f"Error loading custom applications: {e}")

def run_command(command):
    """Run a shell command and return the output"""
    logger.info(f"Running command: {command}")
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            check=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e}")
        logger.error(f"Error output: {e.stderr}")
        return None

def check_syft_installed():
    """Check if Syft is installed"""
    logger.info("Checking if Syft is installed...")
    result = subprocess.run(
        ["which", "syft"], 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    
    if result.returncode != 0:
        logger.warning("Syft not found. Installing Syft...")
        install_syft_command = "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
        try:
            subprocess.run(
                install_syft_command, 
                shell=True, 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            logger.info("Syft installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install Syft: {e}")
            return False
    else:
        logger.info("Syft is already installed")
        return True

def install_application(app):
    """Install an application using apt-get"""
    package_name = app["package"]
    logger.info(f"Installing {app['name']} ({package_name})...")
    
    # Check if package is already installed
    check_cmd = f"dpkg -l | grep -q '^ii\\s*{package_name}\\s'"
    result = subprocess.run(check_cmd, shell=True)
    
    if result.returncode == 0:
        logger.info(f"{package_name} is already installed")
        return True
    
    # Install the package
    try:
        # Use sudo for the installation
        cmd = f"sudo apt-get install -y {package_name}"
        result = subprocess.run(
            cmd, 
            shell=True, 
            check=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        logger.info(f"Successfully installed {package_name}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install {package_name}: {e}")
        logger.error(f"Error output: {e.stderr}")
        return False

def generate_sbom(app):
    """Generate SBOM for an application using Syft"""
    app_name = app["name"]
    package_name = app["package"]
    category = app["category"]
    
    logger.info(f"Generating SBOM for {app_name}...")
    
    # Create filenames
    timestamp = datetime.now().strftime("%Y%m%d")
    sbom_filename = f"{app_name}_{timestamp}_sbom.json"
    sbom_path = os.path.join(DATASET_DIR, sbom_filename)
    
    # Generate SBOM using Syft
    try:
        # Use syft scan command to get the SBOM for the installed package
        cmd = f"syft scan {package_name} -o cyclonedx-json"
        
        # Try alternate commands if the primary one fails
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            sbom_data = result.stdout
        except subprocess.CalledProcessError as e:
            logger.warning(f"First command failed, trying alternative syntax...")
            
            # Try alternative #1: Using "packages" instead of "scan"
            cmd = f"syft packages {package_name} -o cyclonedx-json"
            try:
                result = subprocess.run(
                    cmd, 
                    shell=True, 
                    check=True, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                sbom_data = result.stdout
            except subprocess.CalledProcessError:
                logger.warning(f"Second command failed, trying to scan binary path...")
                
                # Try alternative #2: Get the path to the binary and scan it directly
                which_cmd = f"which {package_name} 2>/dev/null || find /usr/bin /usr/sbin -name '{package_name}*' -type f | head -1"
                bin_path_result = subprocess.run(
                    which_cmd, 
                    shell=True, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                
                if bin_path_result.stdout.strip():
                    bin_path = bin_path_result.stdout.strip()
                    cmd = f"syft scan {bin_path} -o cyclonedx-json"
                    result = subprocess.run(
                        cmd, 
                        shell=True, 
                        check=True, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        universal_newlines=True
                    )
                    sbom_data = result.stdout
                else:
                    # If all else fails, try to scan the system package directly
                    cmd = f"syft scan /var/lib/dpkg/info/{package_name}.list -o cyclonedx-json"
                    result = subprocess.run(
                        cmd, 
                        shell=True, 
                        check=True, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        universal_newlines=True
                    )
                    sbom_data = result.stdout
        
        # Save SBOM to file
        with open(sbom_path, 'w') as f:
            f.write(sbom_data)
        
        logger.info(f"SBOM for {app_name} saved to {sbom_path}")
        
        # Parse the SBOM to add additional metadata
        try:
            sbom_json = json.loads(sbom_data)
            
            # Add metadata if not present
            if "metadata" not in sbom_json:
                sbom_json["metadata"] = {}
            
            # Add component metadata if not present
            if "component" not in sbom_json["metadata"]:
                sbom_json["metadata"]["component"] = {}
            
            # Update component metadata
            component = sbom_json["metadata"]["component"]
            component["name"] = app_name
            component["type"] = "application"
            
            # Add supplier
            if "supplier" not in component:
                component["supplier"] = {"name": app.get("supplier", "unknown")}
            
            # Add properties if not present
            if "properties" not in component:
                component["properties"] = []
            
            # Add or update properties
            properties = component["properties"]
            
            # Function to add or update a property
            def add_or_update_property(name, value):
                for prop in properties:
                    if prop.get("name") == name:
                        prop["value"] = value
                        return
                properties.append({"name": name, "value": value})
            
            add_or_update_property("category", category)
            add_or_update_property("os", "linux")
            add_or_update_property("type", "desktop")
            
            # Save updated SBOM
            with open(sbom_path, 'w') as f:
                json.dump(sbom_json, f, indent=2)
            
            logger.info(f"Updated SBOM metadata for {app_name}")
            
            return sbom_filename, sbom_path
            
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing SBOM JSON for {app_name}: {e}")
            return sbom_filename, sbom_path
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate SBOM for {app_name}: {e}")
        logger.error(f"Error output: {e.stderr}")
        return None, None

def backup_sbom(filename, source_path):
    """Backup an SBOM file to multiple locations"""
    if not os.path.exists(source_path):
        logger.error(f"Source file not found: {source_path}")
        return False
    
    # Copy to sbom_files directory
    sbom_files_path = os.path.join(SBOM_FILES_DIR, filename)
    try:
        shutil.copy2(source_path, sbom_files_path)
        logger.info(f"Backed up SBOM to {sbom_files_path}")
    except Exception as e:
        logger.error(f"Failed to backup to sbom_files: {e}")
    
    # Copy to local backup directory
    local_backup_path = os.path.join(LOCAL_BACKUP_DIR, filename)
    try:
        shutil.copy2(source_path, local_backup_path)
        logger.info(f"Backed up SBOM to {local_backup_path}")
    except Exception as e:
        logger.error(f"Failed to backup to local directory: {e}")
    
    # Copy to Windows directory if available
    if os.path.exists(WINDOWS_DIR):
        windows_backup_path = os.path.join(WINDOWS_DIR, filename)
        try:
            shutil.copy2(source_path, windows_backup_path)
            logger.info(f"Backed up SBOM to Windows directory: {windows_backup_path}")
        except Exception as e:
            logger.error(f"Failed to backup to Windows directory: {e}")
    
    return True

def main():
    """Main function to run the SBOM generation process"""
    logger.info("Starting SBOM generation process")
    
    # Check if script is run with sudo
    if os.geteuid() != 0:
        logger.warning("This script should be run with sudo privileges for installing packages.")
        logger.warning("Some operations might fail without proper permissions.")
    
    # Check if Syft is installed
    if not check_syft_installed():
        logger.error("Failed to install Syft. Exiting.")
        return
    
    # Update package lists
    logger.info("Updating package lists...")
    update_cmd = "sudo apt-get update"
    if run_command(update_cmd) is None:
        logger.error("Failed to update package lists. Continuing anyway...")
    
    successful_sboms = 0
    failed_sboms = 0
    skipped_apps = 0

    # Ask user which applications to process
    print("\nAvailable applications for SBOM generation:")
    for i, app in enumerate(APPLICATIONS):
        print(f"{i+1}. {app['name']} ({app['package']}) - {app['category']}")
    
    print("\nOptions:")
    print("a. Process all applications")
    print("i. Process only already installed applications")
    print("n. Enter application numbers to process (comma-separated)")
    
    choice = input("\nEnter your choice (a/i/n): ").strip().lower()
    
    apps_to_process = []
    
    if choice == 'a':
        apps_to_process = APPLICATIONS
    elif choice == 'i':
        # Filter only installed applications
        for app in APPLICATIONS:
            check_cmd = f"dpkg -l | grep -q '^ii\\s*{app['package']}\\s'"
            result = subprocess.run(check_cmd, shell=True)
            if result.returncode == 0:
                apps_to_process.append(app)
        logger.info(f"Found {len(apps_to_process)} installed applications")
    elif choice == 'n':
        numbers = input("Enter application numbers to process (comma-separated): ").strip()
        try:
            indices = [int(n.strip()) - 1 for n in numbers.split(',')]
            for idx in indices:
                if 0 <= idx < len(APPLICATIONS):
                    apps_to_process.append(APPLICATIONS[idx])
                else:
                    logger.warning(f"Invalid application number: {idx+1}")
        except ValueError:
            logger.error("Invalid input. Processing all applications instead.")
            apps_to_process = APPLICATIONS
    else:
        logger.warning("Invalid choice. Processing all applications.")
        apps_to_process = APPLICATIONS
    
    logger.info(f"Will process {len(apps_to_process)} applications")
    
    for app in apps_to_process:
        app_name = app["name"]
        
        # Try to install the application (or confirm it's installed)
        if not install_application(app):
            logger.warning(f"Skipping SBOM generation for {app_name} due to installation failure")
            skipped_apps += 1
            continue
        
        # Generate SBOM
        sbom_filename, sbom_path = generate_sbom(app)
        if sbom_filename and sbom_path:
            # Backup the SBOM
            if backup_sbom(sbom_filename, sbom_path):
                successful_sboms += 1
            else:
                logger.warning(f"Failed to backup SBOM for {app_name}")
                failed_sboms += 1
        else:
            logger.warning(f"Failed to generate SBOM for {app_name}")
            failed_sboms += 1
    
    # Summary
    logger.info("SBOM generation process completed")
    logger.info(f"Successfully generated and backed up {successful_sboms} SBOMs")
    logger.info(f"Failed to generate {failed_sboms} SBOMs")
    logger.info(f"Skipped {skipped_apps} applications")
    logger.info(f"SBOMs are available in:")
    logger.info(f"  - SBOM Dataset directory: {os.path.abspath(DATASET_DIR)}")
    logger.info(f"  - SBOM Files directory: {os.path.abspath(SBOM_FILES_DIR)}")
    logger.info(f"  - Local backup directory: {os.path.abspath(LOCAL_BACKUP_DIR)}")
    if os.path.exists(WINDOWS_DIR):
        logger.info(f"  - Windows directory: {WINDOWS_DIR}")

if __name__ == "__main__":
    main() 