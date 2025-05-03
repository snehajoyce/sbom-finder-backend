#!/usr/bin/env python3
import os
import sys
import shutil
import argparse
import logging
import glob

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Paths
SBOM_DIR = "./sbom_files/"
DATASET_DIR = "./sbom_files/SBOM/"

def copy_file(filename, force=False):
    """Copy a file from SBOM_DIR to DATASET_DIR"""
    source_path = os.path.join(SBOM_DIR, filename)
    dest_path = os.path.join(DATASET_DIR, filename)
    
    if not os.path.exists(source_path):
        logger.error(f"Source file not found: {source_path}")
        return False
    
    if os.path.exists(dest_path) and not force:
        logger.warning(f"Destination file already exists: {dest_path}")
        logger.warning("Use --force to overwrite")
        return False
    
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        
        # Copy the file
        shutil.copy2(source_path, dest_path)
        logger.info(f"Copied {filename} to dataset directory")
        return True
    except Exception as e:
        logger.error(f"Error copying file: {e}")
        return False

def copy_all_files(force=False):
    """Copy all files from SBOM_DIR to DATASET_DIR"""
    if not os.path.exists(SBOM_DIR):
        logger.error(f"SBOM directory not found: {SBOM_DIR}")
        return False
    
    # Get list of files in SBOM_DIR (not in subdirectories)
    files = [f for f in os.listdir(SBOM_DIR) if os.path.isfile(os.path.join(SBOM_DIR, f))]
    
    if not files:
        logger.warning("No files found in SBOM directory")
        return False
    
    # Count successful copies
    success_count = 0
    for filename in files:
        if copy_file(filename, force):
            success_count += 1
    
    logger.info(f"Copied {success_count} of {len(files)} files to dataset directory")
    return success_count > 0

def main():
    parser = argparse.ArgumentParser(description="Copy SBOM files to dataset directory")
    parser.add_argument("--file", help="Specific file to copy")
    parser.add_argument("--all", action="store_true", help="Copy all files from SBOM_DIR to DATASET_DIR")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files")
    args = parser.parse_args()
    
    # Check if directories exist
    if not os.path.exists(SBOM_DIR):
        logger.error(f"SBOM directory not found: {SBOM_DIR}")
        return 1
    
    os.makedirs(DATASET_DIR, exist_ok=True, mode=0o777)
    
    # Try to fix permissions
    try:
        os.chmod(DATASET_DIR, 0o777)
    except Exception as e:
        logger.warning(f"Could not set permissions on dataset directory: {e}")
        logger.warning("You may need to run with sudo privileges")
    
    # Copy files
    if args.file:
        success = copy_file(args.file, args.force)
    elif args.all:
        success = copy_all_files(args.force)
    else:
        parser.print_help()
        logger.error("Please specify --file or --all")
        return 1
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main()) 