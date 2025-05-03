import os
import requests
import json
import time
import re

# Configuration
DATASET_DIR = os.path.join(os.getcwd(), "SBOM Dataset")
UPLOAD_URL = "http://localhost:5001/api/upload"

def extract_metadata_from_filename(filename):
    """
    Extract metadata from filename using patterns
    Example formats:
    - supplier-appname-os-version.json (acme-firefox-windows-v1.0.json)
    - appname-os-version.json (firefox-windows-98.json)
    - appname-os.json (chrome-android.json)
    """
    base_name = os.path.splitext(filename)[0]
    parts = re.split(r'[-_]', base_name)
    
    # Default values
    metadata = {
        "app_name": parts[0] if parts else "Unknown",
        "category": "Application",
        "operating_system": "Unknown",
        "supplier": "Unknown",
        "manufacturer": "Unknown",
        "version": "1.0",
        "app_binary_type": "desktop",
        "cost": "0",
        "description": ""
    }
    
    # Extract app name (usually first or second part)
    if len(parts) >= 2:
        # Check if first part is a common supplier name
        common_suppliers = ["acme", "microsoft", "google", "apple", "adobe", "mozilla", "oracle"]
        if parts[0].lower() in common_suppliers:
            metadata["supplier"] = parts[0]
            metadata["manufacturer"] = parts[0]
            metadata["app_name"] = parts[1]
        else:
            metadata["app_name"] = parts[0]
    
    # Extract OS
    os_patterns = {
        "windows": ["windows", "win", "win10", "win11"],
        "linux": ["linux", "ubuntu", "fedora", "debian"],
        "macos": ["macos", "mac", "osx"],
        "android": ["android"],
        "ios": ["ios", "iphone", "ipad"]
    }
    
    for os_name, patterns in os_patterns.items():
        for part in parts:
            if part.lower() in patterns:
                metadata["operating_system"] = os_name
                # Set binary type based on OS
                if os_name in ["android", "ios"]:
                    metadata["app_binary_type"] = "mobile"
                elif os_name in ["windows", "linux", "macos"]:
                    metadata["app_binary_type"] = "desktop"
                break
    
    # Extract version (check for parts that start with v or contain numbers with dots)
    version_pattern = re.compile(r'^v?\d+(\.\d+)*$')
    for part in parts:
        if version_pattern.match(part):
            metadata["version"] = part
            break
    
    # Create description
    metadata["description"] = f"{metadata['app_name']} application for {metadata['operating_system']}"
    
    return metadata

def analyze_sbom_content(file_path):
    """Analyze SBOM content to extract additional metadata"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Count components based on different formats
        component_count = 0
        license_set = set()
        
        # Try different SBOM formats
        components = []
        
        # CycloneDX format
        if "components" in data:
            components = data["components"]
        # SPDX format
        elif "packages" in data:
            components = data["packages"]
        # Syft format
        elif "artifacts" in data:
            components = data["artifacts"]
        
        component_count = len(components)
        
        # Extract license information
        for comp in components:
            # CycloneDX format
            if "licenses" in comp:
                for lic in comp.get("licenses", []):
                    if isinstance(lic, dict) and "license" in lic:
                        license_id = lic.get("license", {}).get("id", "")
                        if license_id:
                            license_set.add(license_id)
            
            # SPDX format
            if "licenseConcluded" in comp and comp["licenseConcluded"]:
                license_set.add(comp["licenseConcluded"])
            
            # Additional metadata
            if "supplier" in comp and comp["supplier"] and isinstance(comp["supplier"], str):
                supplier = comp["supplier"]
            elif "supplier" in comp and comp["supplier"] and isinstance(comp["supplier"], dict):
                supplier = comp["supplier"].get("name", "")
                
            if "publisher" in comp:
                publisher = comp["publisher"]
        
        # Look for metadata in document properties
        if "metadata" in data:
            metadata = data["metadata"]
            if "component" in metadata:
                component = metadata["component"]
                # Try to get supplier/manufacturer
                if "supplier" in component and "name" in component["supplier"]:
                    supplier = component["supplier"]["name"]
                if "publisher" in component:
                    publisher = component["publisher"]
        
        return {
            "component_count": component_count,
            "license_count": len(license_set)
        }
    
    except Exception as e:
        print(f"Error analyzing SBOM content: {e}")
        return {
            "component_count": 0,
            "license_count": 0
        }

def upload_sbom(file_path, metadata):
    """Upload a single SBOM file with metadata"""
    filename = os.path.basename(file_path)
    
    try:
            with open(file_path, 'rb') as f:
                files = {'file': (filename, f)}
                response = requests.post(UPLOAD_URL, data=metadata, files=files)

                if response.status_code == 200:
                    print(f"✅ Uploaded: {filename}")
            return True
                else:
            print(f"❌ Failed to upload {filename}: {response.text}")
            return False
    
    except Exception as e:
        print(f"❌ Error uploading {filename}: {e}")
        return False

def upload_all_sboms():
    """Process and upload all SBOMs in the dataset directory"""
    if not os.path.exists(DATASET_DIR):
        print(f"Dataset directory not found: {DATASET_DIR}")
        return
    
    sbom_files = [f for f in os.listdir(DATASET_DIR) if f.endswith('.json')]
    if not sbom_files:
        print("No SBOM files found in dataset directory.")
        return
    
    print(f"Found {len(sbom_files)} SBOM files to process.")
    
    success_count = 0
    
    for filename in sbom_files:
        file_path = os.path.join(DATASET_DIR, filename)
        
        # Extract basic metadata from filename
        metadata = extract_metadata_from_filename(filename)
        
        # Analyze SBOM content for additional metadata
        analysis = analyze_sbom_content(file_path)
        
        # Add analysis results to metadata
        metadata["total_components"] = str(analysis["component_count"])
        metadata["unique_licenses"] = str(analysis["license_count"])
        
        # Upload the SBOM
        if upload_sbom(file_path, metadata):
            success_count += 1
        
        # Avoid overwhelming the server
        time.sleep(0.5)
    
    print(f"\nUpload complete. {success_count} of {len(sbom_files)} files uploaded successfully.")

if __name__ == "__main__":
    upload_all_sboms()
