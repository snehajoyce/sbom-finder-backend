#!/usr/bin/env python3
import os
import json
import shutil
import logging
import sys
from datetime import datetime

# Configuration
DATASET_DIR = "./SBOM Dataset"
LOCAL_BACKUP_DIR = os.path.expanduser("~/local_sbom_backup")
WINDOWS_DIR = "/mnt/c/Users/Gunty Snehajoyce/Documents/SBOM"  # WSL path to Windows location
SBOM_FILES_DIR = "./sbom_files"
TEST_FILE = "test_sbom_backup.json"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("test_backup.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def create_test_sbom():
    """Create a simple test SBOM file"""
    logger.info("Creating test SBOM file")
    
    test_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "serialNumber": f"urn:uuid:test-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "tools": [
                {
                    "vendor": "SBOM Test",
                    "name": "Backup Tester",
                    "version": "1.0.0"
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": "pkg:test/backup-test@1.0.0",
                "name": "backup-test",
                "version": "1.0.0",
                "supplier": {"name": "test-supplier"},
                "properties": [
                    {"name": "category", "value": "test"},
                    {"name": "os", "value": "linux"},
                    {"name": "type", "value": "desktop"}
                ]
            }
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:generic/test-component@1.0.0",
                "name": "test-component",
                "version": "1.0.0",
                "licenses": [
                    {
                        "license": {
                            "id": "MIT"
                        }
                    }
                ]
            }
        ]
    }
    
    # Ensure all directories exist
    for directory in [DATASET_DIR, LOCAL_BACKUP_DIR, SBOM_FILES_DIR]:
        os.makedirs(directory, exist_ok=True)
    
    try:
        os.makedirs(WINDOWS_DIR, exist_ok=True)
        logger.info(f"Windows directory verified/created: {WINDOWS_DIR}")
    except Exception as e:
        logger.warning(f"Could not create Windows directory: {e}")
    
    # Save test SBOM to dataset directory
    dataset_path = os.path.join(DATASET_DIR, TEST_FILE)
    with open(dataset_path, 'w') as f:
        json.dump(test_sbom, f, indent=2)
    
    logger.info(f"Test SBOM created at {dataset_path}")
    return dataset_path

def backup_sbom(source_path):
    """Backup the test SBOM to all backup locations"""
    logger.info("Testing backup functionality")
    
    if not os.path.exists(source_path):
        logger.error(f"Source file not found: {source_path}")
        return False
    
    success = True
    filename = os.path.basename(source_path)
    
    # Test backup to sbom_files directory
    sbom_files_path = os.path.join(SBOM_FILES_DIR, filename)
    try:
        shutil.copy2(source_path, sbom_files_path)
        if os.path.exists(sbom_files_path):
            logger.info(f"✅ Successfully backed up to {sbom_files_path}")
        else:
            logger.error(f"❌ Failed to verify backup at {sbom_files_path}")
            success = False
    except Exception as e:
        logger.error(f"❌ Error backing up to sbom_files: {e}")
        success = False
    
    # Test backup to local backup directory
    local_backup_path = os.path.join(LOCAL_BACKUP_DIR, filename)
    try:
        shutil.copy2(source_path, local_backup_path)
        if os.path.exists(local_backup_path):
            logger.info(f"✅ Successfully backed up to {local_backup_path}")
        else:
            logger.error(f"❌ Failed to verify backup at {local_backup_path}")
            success = False
    except Exception as e:
        logger.error(f"❌ Error backing up to local directory: {e}")
        success = False
    
    # Test backup to Windows directory if available
    if os.path.exists(WINDOWS_DIR):
        windows_backup_path = os.path.join(WINDOWS_DIR, filename)
        try:
            shutil.copy2(source_path, windows_backup_path)
            if os.path.exists(windows_backup_path):
                logger.info(f"✅ Successfully backed up to {windows_backup_path}")
            else:
                logger.error(f"❌ Failed to verify backup at {windows_backup_path}")
                success = False
        except Exception as e:
            logger.error(f"❌ Error backing up to Windows directory: {e}")
            success = False
    else:
        logger.warning("⚠️ Windows directory not available, skipping backup")
    
    return success

def verify_backups():
    """Verify that the backups exist in all locations"""
    logger.info("Verifying backups")
    
    success = True
    
    # Check each location for the test file
    locations = [
        (DATASET_DIR, "Dataset Directory"),
        (SBOM_FILES_DIR, "SBOM Files Directory"),
        (LOCAL_BACKUP_DIR, "Local Backup Directory")
    ]
    
    if os.path.exists(WINDOWS_DIR):
        locations.append((WINDOWS_DIR, "Windows Directory"))
    
    for directory, description in locations:
        test_path = os.path.join(directory, TEST_FILE)
        if os.path.exists(test_path):
            logger.info(f"✅ Found test SBOM in {description}: {test_path}")
            
            # Verify content (optional)
            try:
                with open(test_path, 'r') as f:
                    data = json.load(f)
                if "bomFormat" in data and data["bomFormat"] == "CycloneDX":
                    logger.info(f"✅ Verified content in {description}")
                else:
                    logger.error(f"❌ Content verification failed in {description}")
                    success = False
            except Exception as e:
                logger.error(f"❌ Error verifying content in {description}: {e}")
                success = False
        else:
            logger.error(f"❌ Test SBOM not found in {description}")
            success = False
    
    return success

def cleanup():
    """Clean up by removing the test files"""
    logger.info("Cleaning up test files")
    
    for directory in [DATASET_DIR, SBOM_FILES_DIR, LOCAL_BACKUP_DIR, WINDOWS_DIR]:
        if os.path.exists(directory):
            test_path = os.path.join(directory, TEST_FILE)
            if os.path.exists(test_path):
                try:
                    os.remove(test_path)
                    logger.info(f"✅ Removed test file from {directory}")
                except Exception as e:
                    logger.error(f"❌ Failed to remove test file from {directory}: {e}")

def main():
    """Main test function"""
    logger.info("Starting SBOM backup test")
    
    try:
        # Create the test SBOM
        source_path = create_test_sbom()
        
        # Backup the test SBOM
        backup_success = backup_sbom(source_path)
        
        # Verify backups
        verify_success = verify_backups()
        
        # Report results
        if backup_success and verify_success:
            logger.info("✅ SBOM backup test PASSED! All backups were created and verified successfully.")
        else:
            logger.error("❌ SBOM backup test FAILED! Some backups failed to create or verify.")
        
        # Clean up
        cleanup()
        
    except Exception as e:
        logger.error(f"❌ Test failed with unexpected error: {e}")
    
    logger.info("SBOM backup test completed")

if __name__ == "__main__":
    main() 