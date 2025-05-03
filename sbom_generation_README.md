# SBOM Dataset Generation Tools

This directory contains tools to automatically generate Software Bill of Materials (SBOM) files for a variety of applications, helping you build a comprehensive dataset for the SBOM Finder application.

## Scripts Overview

1. **generate_sbom_dataset.py**: The main script for installing applications and generating SBOMs
2. **custom_apps.json**: Definitions of additional applications to include in the dataset
3. **import_sboms.py**: Tool to import generated SBOMs into the SBOM Finder backend

## Requirements

- Linux system with sudo/root access (Ubuntu recommended)
- Python 3.6+
- `apt` package manager
- Internet connection to download packages

## Setup

1. Install required Python packages:
   ```
   pip install requests
   ```

2. Install Syft (done automatically by the generate_sbom_dataset.py script)

## Generating SBOM Dataset

### Basic Usage

```bash
# Make the script executable
chmod +x generate_sbom_dataset.py

# Run with sudo to install packages
sudo ./generate_sbom_dataset.py
```

This will:
1. Install Syft if not already installed
2. Install at least 50 applications from the predefined categories
3. Generate SBOMs for each application
4. Clean up by removing the installed applications
5. Save all SBOMs to the "./SBOM Dataset" directory
6. Create backup copies in your home directory (~/local_sbom_backup)

### Advanced Options

```bash
# Generate SBOMs for at least 75 applications
sudo ./generate_sbom_dataset.py --min-apps 75

# Keep applications installed after generating SBOMs
sudo ./generate_sbom_dataset.py --keep-installed

# Use custom application definitions
sudo ./generate_sbom_dataset.py --custom-apps custom_apps.json

# Specify a custom backup directory
sudo ./generate_sbom_dataset.py --backup-dir /path/to/backup/folder

# Disable backup completely
sudo ./generate_sbom_dataset.py --no-backup
```

## Local Backup

By default, all generated SBOMs are saved in two locations:
1. The main dataset directory: `./SBOM Dataset/`
2. A backup location in your home directory: `~/local_sbom_backup/`

This ensures that:
- You have quick access to SBOMs in the project directory
- You maintain a separate backup copy on your local system
- SBOMs are preserved even if the project directory is deleted

You can customize the backup location with the `--backup-dir` option or disable it with `--no-backup`.

## Importing SBOMs to the Backend

After generating the SBOM dataset, you can import it into the SBOM Finder backend:

```bash
# Start the backend server first (in a separate terminal)
cd /path/to/sbom_finder_backend
source sbom_env/bin/activate
python app.py

# Then import the SBOMs
python import_sboms.py
```

### Import Options

```bash
# Specify a different dataset directory
python import_sboms.py --dataset-dir /path/to/sboms

# Specify a different API URL
python import_sboms.py --api-url http://localhost:5001/api/upload

# Limit the number of SBOMs to import
python import_sboms.py --limit 20
```

## Customizing the Dataset

You can customize the application list by editing the `APPLICATIONS` dictionary in `generate_sbom_dataset.py` or by creating your own custom JSON file with the same structure as `custom_apps.json`:

```json
{
  "category_name": [
    {"name": "package_name", "os": "linux", "type": "desktop", "supplier": "supplier_name"},
    ...
  ],
  ...
}
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Make sure to run the generate script with sudo
2. **Package Not Found**: Some packages might not be available in your repositories
3. **Syft Installation Failed**: Check your internet connection and firewall settings
4. **API Connection Error**: Ensure the SBOM Finder backend is running

### Log File

The script creates a detailed log file `sbom_generation.log` in the current directory. Check this file for troubleshooting information.

## Contributing

Feel free to enhance these scripts by:

1. Adding more application categories
2. Supporting additional package managers (beyond apt)
3. Improving error handling and recovery
4. Adding support for Windows or macOS applications 