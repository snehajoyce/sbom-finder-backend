#!/usr/bin/env python3
import os
import json
import sys
import sqlite3
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Paths
SBOM_DIR = "./sbom_files/"
DATASET_DIR = "./sbom_files/SBOM/"
DB_PATH = "./instance/sboms.db"

def get_sbom_file_path(filename):
    """Find SBOM file in different directories"""
    # Check SBOM_DIR
    file_path = os.path.join(SBOM_DIR, filename)
    if os.path.exists(file_path):
        logger.info(f"Found {filename} in {SBOM_DIR}")
        return file_path
    
    # Check DATASET_DIR
    file_path = os.path.join(DATASET_DIR, filename)
    if os.path.exists(file_path):
        logger.info(f"Found {filename} in {DATASET_DIR}")
        return file_path
    
    logger.error(f"File {filename} not found in any directory")
    return None

def extract_components_from_sbom(sbom_data):
    """Extract components from SBOM based on format (CycloneDX, SPDX, etc.)"""
    # Try CycloneDX format
    if "components" in sbom_data:
        return sbom_data.get("components", [])
    
    # Try SPDX format
    if "packages" in sbom_data:
        return sbom_data.get("packages", [])
    
    # Try Syft format
    if "artifacts" in sbom_data:
        return sbom_data.get("artifacts", [])
    
    # Default fallback
    return []

def get_component_licenses(component):
    """Extract license information from a component"""
    licenses = []
    
    # Handle CycloneDX format
    if "licenses" in component:
        for lic in component.get("licenses", []):
            if isinstance(lic, dict):
                if "license" in lic and isinstance(lic["license"], dict):
                    licenses.append(lic["license"].get("id", "Unknown"))
                elif "expression" in lic:
                    licenses.append(lic["expression"])
    
    # Handle SPDX format
    if "licenseConcluded" in component and component["licenseConcluded"]:
        licenses.append(component["licenseConcluded"])
    
    # Handle Syft format
    if "licenseDeclared" in component and component["licenseDeclared"]:
        licenses.append(component["licenseDeclared"])
    
    return licenses if licenses else ["Unknown"]

def get_sbom_data_and_meta(filename):
    """Get SBOM data and metadata for a file - simulates the Flask app's function"""
    # Get the file path
    file_path = get_sbom_file_path(filename)
    if not file_path:
        return None, None
    
    # Load SBOM data
    try:
        with open(file_path, 'r') as f:
            sbom_data = json.load(f)
    except Exception as e:
        logger.error(f"Error loading SBOM data for {filename}: {e}")
        return None, None
    
    # Get metadata from database
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT app_name, category, operating_system, app_binary_type, supplier, manufacturer, version, total_components, unique_licenses FROM sbom WHERE filename = ?", (filename,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            metadata = {
                "filename": filename,
                "app_name": result[0],
                "category": result[1] or "Unknown",
                "operating_system": result[2] or "Unknown",
                "app_binary_type": result[3] or "Unknown",
                "supplier": result[4] or "Unknown",
                "manufacturer": result[5] or "Unknown",
                "version": result[6] or "Unknown",
                "total_components": result[7] or 0,
                "unique_licenses": result[8] or 0
            }
        else:
            metadata = {
                "filename": filename,
                "app_name": os.path.splitext(filename)[0],
                "category": "Unknown",
                "operating_system": "Unknown",
                "app_binary_type": "Unknown",
                "supplier": "Unknown",
                "manufacturer": "Unknown",
                "version": "Unknown",
                "total_components": 0,
                "unique_licenses": 0
            }
        
        return sbom_data, metadata
    except Exception as e:
        logger.error(f"Error getting metadata for {filename}: {e}")
        return sbom_data, {
            "filename": filename,
            "app_name": os.path.splitext(filename)[0],
            "category": "Unknown",
            "operating_system": "Unknown",
            "app_binary_type": "Unknown",
            "supplier": "Unknown",
            "manufacturer": "Unknown",
            "version": "Unknown"
        }

def load_sbom_from_db():
    """Load SBOM information from database and simulate API response"""
    try:
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get first 5 records from database
        cursor.execute("SELECT id, filename, app_name, category, operating_system FROM sbom LIMIT 5")
        sboms = cursor.fetchall()
        
        # Display results
        logger.info(f"Found {len(sboms)} SBOM records in database")
        for sbom in sboms:
            logger.info(f"SBOM: {sbom}")
            
            # Try to load the actual file using the Flask app's method
            filename = sbom[1]  # filename is the second column
            sbom_data, metadata = get_sbom_data_and_meta(filename)
            
            if sbom_data:
                logger.info(f"Successfully loaded SBOM data for {filename}")
                
                # Test component extraction like the API would do
                components = extract_components_from_sbom(sbom_data)
                logger.info(f"Extracted {len(components)} components from {filename}")
                
                # Test response formatting like the API endpoint
                response = {
                    "metadata": metadata,
                    "sbom_data": sbom_data
                }
                
                # Try to serialize to JSON - this would happen when the API returns the response
                try:
                    json_data = json.dumps(response)
                    logger.info(f"Successfully serialized response for {filename}")
                except Exception as e:
                    logger.error(f"Failed to serialize response for {filename}: {e}")
            else:
                logger.error(f"Failed to load SBOM data for {filename}")
        
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")

def test_all_sboms():
    """Test loading all SBOMs in the database"""
    try:
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get all SBOM filenames
        cursor.execute("SELECT filename FROM sbom")
        filenames = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        logger.info(f"Testing all {len(filenames)} SBOMs in the database")
        
        # Test each SBOM
        success = 0
        failed = 0
        
        for filename in filenames:
            sbom_data, metadata = get_sbom_data_and_meta(filename)
            
            if sbom_data:
                # Test component extraction
                components = extract_components_from_sbom(sbom_data)
                
                # Create response object
                response = {
                    "metadata": metadata,
                    "sbom_data": sbom_data
                }
                
                # Try to serialize to JSON
                try:
                    json_data = json.dumps(response)
                    success += 1
                except Exception as e:
                    logger.error(f"Failed to serialize response for {filename}: {e}")
                    failed += 1
            else:
                logger.error(f"Failed to load SBOM data for {filename}")
                failed += 1
        
        logger.info(f"SBOM loading test results: {success} successful, {failed} failed")
    except Exception as e:
        logger.error(f"Error testing SBOMs: {e}")

def main():
    logger.info("Starting SBOM load test")
    
    # Check if database exists
    if not os.path.exists(DB_PATH):
        logger.error(f"Database file not found at {DB_PATH}")
        return
    
    # Check if SBOM directories exist
    if not os.path.exists(SBOM_DIR):
        logger.error(f"SBOM directory not found at {SBOM_DIR}")
    else:
        logger.info(f"SBOM directory exists at {SBOM_DIR}")
    
    if not os.path.exists(DATASET_DIR):
        logger.error(f"Dataset directory not found at {DATASET_DIR}")
    else:
        logger.info(f"Dataset directory exists at {DATASET_DIR}")
    
    # Test loading a few SBOMs
    logger.info("Testing loading a few SBOMs:")
    load_sbom_from_db()
    
    # Test all SBOMs
    logger.info("\nTesting loading ALL SBOMs:")
    test_all_sboms()
    
    logger.info("SBOM load test completed")

if __name__ == "__main__":
    main() 