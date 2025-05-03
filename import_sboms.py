#!/usr/bin/env python3
import os
import json
import glob
import sqlite3
import logging
import sys
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("import_sboms.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
DATASET_DIR = "./sbom_files/SBOM"
SBOM_FILES_DIR = "./sbom_files"
DB_PATH = "./instance/sboms.db"

def ensure_db_exists():
    """Ensure the database exists and has the correct schema"""
    logger.info(f"Checking database at {DB_PATH}")
    
    # Make sure the directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    # Connect to the database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if SBOM table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sbom'")
    if cursor.fetchone() is None:
        logger.info("Creating SBOM table in database")
        
        # Create the SBOM table
        cursor.execute('''
            CREATE TABLE sbom (
                id INTEGER PRIMARY KEY,
                filename TEXT UNIQUE NOT NULL,
                app_name TEXT NOT NULL,
                category TEXT,
                operating_system TEXT,
                app_binary_type TEXT,
                supplier TEXT,
                manufacturer TEXT,
                version TEXT,
                cost REAL DEFAULT 0.0,
                total_components INTEGER DEFAULT 0,
                unique_licenses INTEGER DEFAULT 0,
                description TEXT,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        logger.info("SBOM table created successfully")
    else:
        logger.info("SBOM table already exists")
    
    conn.close()

def extract_sbom_metadata(sbom_path):
    """Extract metadata from SBOM file"""
    try:
        with open(sbom_path, 'r') as f:
            sbom_data = json.load(f)
        
        # Default metadata
        metadata = {
            "app_name": os.path.basename(sbom_path).split('_')[0],
            "category": "unknown",
            "operating_system": "unknown",
            "app_binary_type": "desktop",
            "supplier": "unknown",
            "manufacturer": "unknown",
            "version": "unknown",
            "total_components": 0,
            "unique_licenses": 0
        }
        
        # Extract components for counting
        components = []
        if "components" in sbom_data:
            components = sbom_data["components"]
        elif "artifacts" in sbom_data:
            components = sbom_data["artifacts"]
        elif "packages" in sbom_data:
            components = sbom_data["packages"]
        
        # Count components
        metadata["total_components"] = len(components)
        
        # Extract metadata from CycloneDX format
        if "metadata" in sbom_data and "component" in sbom_data["metadata"]:
            component = sbom_data["metadata"]["component"]
            
            if "name" in component:
                metadata["app_name"] = component["name"]
            
            if "version" in component:
                metadata["version"] = component["version"]
            
            if "supplier" in component and "name" in component["supplier"]:
                metadata["supplier"] = component["supplier"]["name"]
                metadata["manufacturer"] = component["supplier"]["name"]
            
            # Extract properties
            if "properties" in component:
                for prop in component["properties"]:
                    if prop.get("name") == "category":
                        metadata["category"] = prop.get("value")
                    elif prop.get("name") == "os":
                        metadata["operating_system"] = prop.get("value")
                    elif prop.get("name") == "type":
                        metadata["app_binary_type"] = prop.get("value")
        
        # Count unique licenses
        unique_licenses = set()
        for comp in components:
            if "licenses" in comp:
                for lic in comp["licenses"]:
                    if isinstance(lic, dict):
                        if "license" in lic and isinstance(lic["license"], dict):
                            unique_licenses.add(lic["license"].get("id", "Unknown"))
                        elif "expression" in lic:
                            unique_licenses.add(lic["expression"])
        
        metadata["unique_licenses"] = len(unique_licenses)
        
        # Try to extract OS from filename if not found
        if metadata["operating_system"] == "unknown":
            filename = os.path.basename(sbom_path)
            
            # Common patterns in our filenames
            for os_name in ["windows", "linux", "macos", "android", "ios"]:
                if os_name in filename.lower():
                    metadata["operating_system"] = os_name
                    break
        
        # Try to extract app type from filename if not found
        if metadata["app_binary_type"] == "desktop":
            filename = os.path.basename(sbom_path)
            
            # Common patterns in our filenames
            for app_type in ["mobile", "web", "server", "service"]:
                if app_type in filename.lower():
                    metadata["app_binary_type"] = app_type
                    break
        
        return metadata
    
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing JSON from {sbom_path}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error extracting metadata from {sbom_path}: {e}")
        return None

def import_sbom(sbom_path, conn):
    """Import a single SBOM file into the database"""
    filename = os.path.basename(sbom_path)
    
    # Extract metadata
    metadata = extract_sbom_metadata(sbom_path)
    if not metadata:
        logger.error(f"Failed to extract metadata from {filename}")
        return False
    
    try:
        cursor = conn.cursor()
        
        # Check if SBOM already exists in database
        cursor.execute("SELECT id FROM sbom WHERE filename = ?", (filename,))
        existing = cursor.fetchone()
        
        if existing:
            logger.info(f"SBOM {filename} already exists in database, updating...")
            
            # Update existing record
            cursor.execute("""
                UPDATE sbom SET
                    app_name = ?,
                    category = ?,
                    operating_system = ?,
                    app_binary_type = ?,
                    supplier = ?,
                    manufacturer = ?,
                    version = ?,
                    total_components = ?,
                    unique_licenses = ?
                WHERE filename = ?
            """, (
                metadata["app_name"],
                metadata["category"],
                metadata["operating_system"],
                metadata["app_binary_type"],
                metadata["supplier"],
                metadata["manufacturer"],
                metadata["version"],
                metadata["total_components"],
                metadata["unique_licenses"],
                filename
            ))
        else:
            logger.info(f"Importing new SBOM {filename}...")
            
            # Insert new record
            cursor.execute("""
                INSERT INTO sbom (
                    filename, app_name, category, operating_system, app_binary_type,
                    supplier, manufacturer, version, total_components, unique_licenses
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                filename,
                metadata["app_name"],
                metadata["category"],
                metadata["operating_system"],
                metadata["app_binary_type"],
                metadata["supplier"],
                metadata["manufacturer"],
                metadata["version"],
                metadata["total_components"],
                metadata["unique_licenses"]
            ))
        
        conn.commit()
        return True
    
    except sqlite3.Error as e:
        logger.error(f"Database error while importing {filename}: {e}")
        conn.rollback()
        return False
    except Exception as e:
        logger.error(f"Unexpected error while importing {filename}: {e}")
        conn.rollback()
        return False

def main():
    """Main function to import all SBOMs into the database"""
    logger.info("Starting SBOM import process")
    
    # Ensure database exists
    ensure_db_exists()
    
    # Get all SBOM files from both directories
    sbom_files = []
    
    # DATASET_DIR
    if os.path.exists(DATASET_DIR):
        dataset_sboms = glob.glob(os.path.join(DATASET_DIR, "*.json"))
        sbom_files.extend(dataset_sboms)
        logger.info(f"Found {len(dataset_sboms)} SBOM files in {DATASET_DIR}")
    
    # SBOM_FILES_DIR
    if os.path.exists(SBOM_FILES_DIR):
        sbom_dir_files = glob.glob(os.path.join(SBOM_FILES_DIR, "*.json"))
        
        # Only add files not already in the list
        new_files = [f for f in sbom_dir_files if os.path.basename(f) not in [os.path.basename(x) for x in sbom_files]]
        sbom_files.extend(new_files)
        logger.info(f"Found {len(new_files)} additional SBOM files in {SBOM_FILES_DIR}")
    
    if not sbom_files:
        logger.warning("No SBOM files found")
        return
    
    # Connect to database
    conn = sqlite3.connect(DB_PATH)
    
    # Import each SBOM
    successful = 0
    failed = 0
    
    for sbom_path in sbom_files:
        if import_sbom(sbom_path, conn):
            successful += 1
        else:
            failed += 1
    
    # Close connection
    conn.close()
    
    # Summary
    logger.info("SBOM import process completed")
    logger.info(f"Successfully imported {successful} SBOMs")
    if failed > 0:
        logger.warning(f"Failed to import {failed} SBOMs")
    
    # Print total count in database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM sbom")
    total_count = cursor.fetchone()[0]
    conn.close()
    
    logger.info(f"Total SBOMs in database: {total_count}")

if __name__ == "__main__":
    main() 