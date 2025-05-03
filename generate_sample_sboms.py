#!/usr/bin/env python3
import os
import json
import shutil
import random
import re
from datetime import datetime

# Configuration
DATASET_DIR = "./SBOM Dataset"
LOCAL_BACKUP_DIR = os.path.expanduser("~/local_sbom_backup")
WINDOWS_DIR = "/mnt/c/Users/Gunty Snehajoyce/Documents/SBOM"  # WSL path to Windows location

# Ensure directories exist
os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(LOCAL_BACKUP_DIR, exist_ok=True)
try:
    os.makedirs(WINDOWS_DIR, exist_ok=True)
    print(f"Windows directory created: {WINDOWS_DIR}")
except Exception as e:
    print(f"Could not create Windows directory: {e}")

def log_message(message):
    """Log a message with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    print(log_entry)

# Define a comprehensive list of applications across platforms
APPLICATION_TEMPLATES = {
    "browsers": [
        {"name": "firefox", "supplier": "mozilla", "platforms": ["windows", "macos", "linux"]},
        {"name": "chrome", "supplier": "google", "platforms": ["windows", "macos", "linux"]},
        {"name": "edge", "supplier": "microsoft", "platforms": ["windows", "macos"]},
        {"name": "safari", "supplier": "apple", "platforms": ["macos", "ios"]},
        {"name": "opera", "supplier": "opera", "platforms": ["windows", "macos", "linux"]},
        {"name": "brave", "supplier": "brave", "platforms": ["windows", "macos", "linux"]},
    ],
    "productivity": [
        {"name": "office", "supplier": "microsoft", "platforms": ["windows", "macos"]},
        {"name": "libreoffice", "supplier": "libreoffice", "platforms": ["windows", "macos", "linux"]},
        {"name": "onlyoffice", "supplier": "onlyoffice", "platforms": ["windows", "macos", "linux"]},
        {"name": "pages", "supplier": "apple", "platforms": ["macos", "ios"]},
        {"name": "numbers", "supplier": "apple", "platforms": ["macos", "ios"]},
        {"name": "keynote", "supplier": "apple", "platforms": ["macos", "ios"]},
    ],
    "media_players": [
        {"name": "vlc", "supplier": "videolan", "platforms": ["windows", "macos", "linux", "android", "ios"]},
        {"name": "kodi", "supplier": "xbmc", "platforms": ["windows", "macos", "linux", "android"]},
        {"name": "spotify", "supplier": "spotify", "platforms": ["windows", "macos", "linux", "android", "ios"]},
        {"name": "itunes", "supplier": "apple", "platforms": ["windows", "macos"]},
        {"name": "winamp", "supplier": "winamp", "platforms": ["windows"]},
        {"name": "mpc-hc", "supplier": "mpc", "platforms": ["windows"]},
    ],
    "photo_video": [
        {"name": "photoshop", "supplier": "adobe", "platforms": ["windows", "macos"]},
        {"name": "gimp", "supplier": "gimp", "platforms": ["windows", "macos", "linux"]},
        {"name": "lightroom", "supplier": "adobe", "platforms": ["windows", "macos", "ios", "android"]},
        {"name": "premiere", "supplier": "adobe", "platforms": ["windows", "macos"]},
        {"name": "finalcutpro", "supplier": "apple", "platforms": ["macos"]},
        {"name": "davinciresolve", "supplier": "blackmagic", "platforms": ["windows", "macos", "linux"]},
    ],
    "development": [
        {"name": "vscode", "supplier": "microsoft", "platforms": ["windows", "macos", "linux"]},
        {"name": "visualstudio", "supplier": "microsoft", "platforms": ["windows", "macos"]},
        {"name": "xcode", "supplier": "apple", "platforms": ["macos"]},
        {"name": "androidstudio", "supplier": "google", "platforms": ["windows", "macos", "linux"]},
        {"name": "intellijidea", "supplier": "jetbrains", "platforms": ["windows", "macos", "linux"]},
        {"name": "eclipse", "supplier": "eclipse", "platforms": ["windows", "macos", "linux"]},
        {"name": "sublimetext", "supplier": "sublime", "platforms": ["windows", "macos", "linux"]},
    ],
    "gaming": [
        {"name": "steam", "supplier": "valve", "platforms": ["windows", "macos", "linux"]},
        {"name": "epicgames", "supplier": "epic", "platforms": ["windows", "macos"]},
        {"name": "battlenet", "supplier": "blizzard", "platforms": ["windows", "macos"]},
        {"name": "origin", "supplier": "ea", "platforms": ["windows", "macos"]},
        {"name": "gog", "supplier": "gog", "platforms": ["windows", "macos"]},
        {"name": "minecraft", "supplier": "mojang", "platforms": ["windows", "macos", "linux", "android", "ios"]},
    ],
    "security": [
        {"name": "avast", "supplier": "avast", "platforms": ["windows", "macos", "android"]},
        {"name": "norton", "supplier": "symantec", "platforms": ["windows", "macos", "android", "ios"]},
        {"name": "mcafee", "supplier": "mcafee", "platforms": ["windows", "macos", "android", "ios"]},
        {"name": "kaspersky", "supplier": "kaspersky", "platforms": ["windows", "macos", "android", "ios"]},
        {"name": "bitdefender", "supplier": "bitdefender", "platforms": ["windows", "macos", "android", "ios"]},
        {"name": "malwarebytes", "supplier": "malwarebytes", "platforms": ["windows", "macos"]},
    ],
    "messaging": [
        {"name": "skype", "supplier": "microsoft", "platforms": ["windows", "macos", "linux", "android", "ios"]},
        {"name": "teams", "supplier": "microsoft", "platforms": ["windows", "macos", "linux", "android", "ios"]},
        {"name": "zoom", "supplier": "zoom", "platforms": ["windows", "macos", "linux", "android", "ios"]},
        {"name": "slack", "supplier": "salesforce", "platforms": ["windows", "macos", "linux", "android", "ios"]},
        {"name": "discord", "supplier": "discord", "platforms": ["windows", "macos", "linux", "android", "ios"]},
        {"name": "telegram", "supplier": "telegram", "platforms": ["windows", "macos", "linux", "android", "ios"]},
        {"name": "whatsapp", "supplier": "meta", "platforms": ["windows", "macos", "android", "ios"]},
    ],
    "utilities": [
        {"name": "7zip", "supplier": "7zip", "platforms": ["windows"]},
        {"name": "winrar", "supplier": "rarlab", "platforms": ["windows"]},
        {"name": "ccleaner", "supplier": "piriform", "platforms": ["windows"]},
        {"name": "teamviewer", "supplier": "teamviewer", "platforms": ["windows", "macos", "linux", "android", "ios"]},
        {"name": "anydesk", "supplier": "anydesk", "platforms": ["windows", "macos", "linux", "android", "ios"]},
        {"name": "cleanmymac", "supplier": "macpaw", "platforms": ["macos"]},
    ],
}

# License information
COMMON_LICENSES = [
    "MIT", "Apache-2.0", "GPL-3.0", "GPL-2.0", "BSD-3-Clause", "BSD-2-Clause",
    "LGPL-2.1", "LGPL-3.0", "MPL-2.0", "ISC", "Unlicense", "Proprietary"
]

# Component categories
COMPONENT_CATEGORIES = [
    "library", "framework", "runtime", "application", "operating-system",
    "device", "firmware", "container", "platform", "file"
]

def generate_random_version():
    """Generate a random version string"""
    major = random.randint(1, 10)
    minor = random.randint(0, 20)
    patch = random.randint(0, 99)
    return f"{major}.{minor}.{patch}"

def generate_random_date():
    """Generate a random date in the last 5 years"""
    year = random.randint(2018, 2025)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{year}-{month:02d}-{day:02d}T00:00:00Z"

def generate_random_component_name(app_name):
    """Generate a random component name related to the app"""
    prefixes = ["lib", "core", "api", "module", "plugin", "service", "util", "framework", "engine", "sdk"]
    suffixes = ["", "-js", "-lib", "-core", "-api", "-utils", "-common", "-base", "-client", "-server"]
    
    # Either use app name as prefix or choose a random prefix
    if random.choice([True, False]):
        name_part = f"{app_name}-{random.choice(prefixes)}"
    else:
        name_part = f"{random.choice(prefixes)}-{app_name}"
    
    return name_part + random.choice(suffixes)

def create_sample_sbom(name, supplier, os_name, app_type="desktop", version=None, min_components=5, max_components=30):
    """Create a sample SBOM file with random but realistic data"""
    log_message(f"Creating sample SBOM for {name} on {os_name}")
    
    # Use provided version or generate random one
    if not version:
        version = generate_random_version()
    
    # Create a basic CycloneDX SBOM structure
    sbom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "serialNumber": f"urn:uuid:{os.urandom(16).hex()}",
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "tools": [
                {
                    "vendor": "SBOM Finder",
                    "name": "SBOM Generator",
                    "version": "1.0.0"
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": f"pkg:{supplier}/{name}@{version}",
                "name": name,
                "version": version,
                "supplier": {"name": supplier},
                "cpe": f"cpe:2.3:a:{supplier}:{name}:{version}:*:*:*:*:*:*:*",
                "properties": [
                    {"name": "os", "value": os_name},
                    {"name": "type", "value": app_type}
                ]
            }
        },
        "components": []
    }
    
    # Determine number of components
    num_components = random.randint(min_components, max_components)
    
    # Add some dependencies (random components)
    used_names = set()
    for i in range(num_components):
        # Generate a unique component name
        while True:
            component_name = generate_random_component_name(name)
            if component_name not in used_names:
                used_names.add(component_name)
                break
        
        component_version = generate_random_version()
        component_type = random.choice(COMPONENT_CATEGORIES)
        
        # Generate licenses (1 or 2)
        license_count = random.choice([1, 1, 1, 2])  # more likely to have 1
        licenses = []
        for _ in range(license_count):
            license_id = random.choice(COMMON_LICENSES)
            licenses.append({
                "license": {
                    "id": license_id
                }
            })
        
        sbom_data["components"].append({
            "type": component_type,
            "bom-ref": f"pkg:generic/{component_name}@{component_version}",
            "name": component_name,
            "version": component_version,
            "purl": f"pkg:generic/{component_name}@{component_version}",
            "licenses": licenses,
            "properties": [
                {"name": "last-modified", "value": generate_random_date()}
            ]
        })
    
    # Create the filename based on the parameters
    filename = f"{supplier}-{name}-{os_name}-{app_type}.json"
    file_path = os.path.join(DATASET_DIR, filename)
    
    # Save the SBOM to the main dataset directory
    with open(file_path, 'w') as f:
        json.dump(sbom_data, f, indent=2)
    
    log_message(f"✅ Saved SBOM to {file_path}")
    return filename, file_path

def backup_sbom(filename, source_path, backup_dir):
    """Backup an SBOM file to the specified directory"""
    backup_path = os.path.join(backup_dir, filename)
    shutil.copy2(source_path, backup_path)
    log_message(f"✅ Backed up SBOM to {backup_path}")
    return backup_path

def main():
    log_message("Starting SBOM sample generation")
    
    # Process each template and generate variants
    total_generated = 0
    total_categories = 0
    
    # Track the number of SBOMs per platform for reporting
    platform_counts = {
        "windows": 0,
        "macos": 0,
        "linux": 0,
        "android": 0,
        "ios": 0
    }
    
    for category, apps in APPLICATION_TEMPLATES.items():
        log_message(f"Processing category: {category}")
        category_count = 0
        total_categories += 1
        
        for app in apps:
            app_name = app["name"]
            supplier = app["supplier"]
            
            for platform in app["platforms"]:
                # Choose random app version
                version = generate_random_version()
                
                # Determine app type (mobile platforms are mobile, others are desktop)
                app_type = "mobile" if platform in ["android", "ios"] else "desktop"
                
                # Create the SBOM
                filename, file_path = create_sample_sbom(
                    app_name, 
                    supplier, 
                    platform, 
                    app_type, 
                    version, 
                    min_components=5 if app_type == "mobile" else 10,
                    max_components=20 if app_type == "mobile" else 50
                )
                
                # Backup to local directory
                backup_sbom(filename, file_path, LOCAL_BACKUP_DIR)
                
                # Backup to Windows directory
                try:
                    if os.path.exists(WINDOWS_DIR):
                        backup_sbom(filename, file_path, WINDOWS_DIR)
                except Exception as e:
                    log_message(f"⚠️ Warning: Could not backup to Windows directory: {e}")
                
                category_count += 1
                total_generated += 1
                platform_counts[platform] += 1
        
        log_message(f"✅ Generated {category_count} SBOMs for category: {category}")
    
    # Final statistics
    log_message(f"✅ SBOM generation complete!")
    log_message(f"Total generated: {total_generated} SBOMs across {total_categories} categories")
    log_message(f"Platform distribution:")
    for platform, count in platform_counts.items():
        log_message(f"  - {platform}: {count} SBOMs")
    
    log_message(f"Files are available in:")
    log_message(f"  - SBOM Dataset directory: {os.path.abspath(DATASET_DIR)}")
    log_message(f"  - Local backup directory: {os.path.abspath(LOCAL_BACKUP_DIR)}")
    if os.path.exists(WINDOWS_DIR):
        log_message(f"  - Windows directory: C:\\Users\\Gunty Snehajoyce\\Documents\\SBOM")

if __name__ == "__main__":
    main() 