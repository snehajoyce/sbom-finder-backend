# SBOM Finder

A comprehensive tool for discovering, analyzing, and comparing Software Bill of Materials (SBOM) for various applications across different platforms.

## Features

- **Search SBOMs** by name, category, operating system, app binary type (mobile, desktop) with partial and fuzzy matching
- **Display SBOM** for selected applications, including components and license information
- **Compare SBOMs** side by side to identify common and unique components
- **View statistics** about SBOMs by category, operating system, supplier, or manufacturer
- **Support for multiple platforms**: Windows, macOS, Linux, iOS, and Android
- **Cross-platform application** support for desktop and mobile applications

## Backend Setup

1. Clone this repository:
```
git clone <repository-url>
cd sbom_finder_backend
```

2. Install the required dependencies:
```
pip install -r requirements.txt
```

3. Initialize the database:
```
python app.py
```

4. To upload SBOM dataset files:
```
python upload_dataset.py
```

## API Endpoints

### Search and Retrieval
- `GET /api/sboms` - List all SBOM filenames
- `GET /api/sboms/metadata` - Get metadata for all SBOMs
- `GET /api/sbom/<filename>` - Get specific SBOM file contents
- `GET /api/search` - Search SBOMs by various criteria
- `GET /api/suggestions` - Get autocomplete suggestions for search fields

### Analysis and Comparison
- `POST /api/search-components` - Search for components within a specific SBOM
- `POST /api/compare` - Compare two SBOMs side by side
- `GET /api/statistics` - Get statistical information about SBOMs
- `GET /api/platform-stats` - Get platform-specific statistics

### SBOM Management
- `POST /api/upload` - Upload SBOM with metadata
- `POST /api/generate-sbom` - Auto-generate SBOM from uploaded executable using Syft

## Directory Structure

- `app.py` - Main Flask application
- `upload_dataset.py` - Script to process and upload SBOM dataset
- `sbom_files/` - Storage for uploaded SBOMs
- `uploads/` - Temporary storage for uploaded executables
- `SBOM Dataset/` - Directory for SBOM dataset files

## Requirements

- Python 3.8+
- Flask and Flask-SQLAlchemy
- Syft (for SBOM generation)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Resources

- [CISA SBOM Information](https://www.cisa.gov/sbom)
- [NIST Software Security in Supply Chains](https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity/software-security-supply-chains-software-1) # Triggering workflow
