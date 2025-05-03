from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from collections import Counter
import os
import json
import subprocess
import uuid
import re
from sqlalchemy import or_, func, and_

# Initialize Flask app
app = Flask(__name__)
# Enable CORS for all routes and origins
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]}})

# File storage path
SBOM_DIR = "./sbom_files/"
UPLOAD_DIR = "./uploads/"
DATASET_DIR = "./sbom_files/SBOM/"
os.makedirs(SBOM_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DATASET_DIR, exist_ok=True)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sboms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Enhanced SBOM Database Model
class SBOM(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), unique=True, nullable=False)
    app_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50))
    operating_system = db.Column(db.String(50))
    app_binary_type = db.Column(db.String(50))  # mobile, desktop, web, etc.
    supplier = db.Column(db.String(100))
    manufacturer = db.Column(db.String(100))
    version = db.Column(db.String(50))
    cost = db.Column(db.Float, default=0.0)
    total_components = db.Column(db.Integer, default=0)
    unique_licenses = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

# Home route
@app.route('/')
def home():
    return "Welcome to SBOM Finder Backend!"

# List all SBOM filenames
@app.route('/api/sboms', methods=['GET'])
def list_sboms():
    sboms = [s.filename for s in SBOM.query.all()]
    return jsonify(sboms)

# Get metadata for all SBOMs
@app.route('/api/sboms/metadata', methods=['GET'])
def list_sboms_metadata():
    sboms = SBOM.query.all()
    result = []
    for sbom in sboms:
        result.append({
            "id": sbom.id,
            "filename": sbom.filename,
            "app_name": sbom.app_name,
            "category": sbom.category,
            "operating_system": sbom.operating_system,
            "supplier": sbom.supplier,
            "manufacturer": sbom.manufacturer,
            "version": sbom.version,
            "binary_type": sbom.app_binary_type,
            "upload_date": sbom.upload_date.isoformat() if sbom.upload_date else None,
            "total_components": sbom.total_components,
            "unique_licenses": sbom.unique_licenses
        })
    return jsonify(result)

# Get specific SBOM file contents
@app.route('/api/sbom/<filename>', methods=['GET'])
def get_sbom(filename):
    # Check if file exists in SBOM_DIR
    file_path = os.path.join(SBOM_DIR, filename)
    if not os.path.exists(file_path):
        # Try DATASET_DIR if not found in SBOM_DIR
        file_path = os.path.join(DATASET_DIR, filename)
        if not os.path.exists(file_path):
            return jsonify({"error": "SBOM not found", "filename": filename}), 404
    
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Get metadata from database
        sbom = SBOM.query.filter_by(filename=filename).first()
        metadata = {}
        if sbom:
            metadata = {
                "app_name": sbom.app_name,
                "category": sbom.category,
                "operating_system": sbom.operating_system,
                "supplier": sbom.supplier,
                "manufacturer": sbom.manufacturer,
                "version": sbom.version,
                "binary_type": sbom.app_binary_type,
                "total_components": sbom.total_components,
                "unique_licenses": sbom.unique_licenses
            }
        else:
            # If no metadata in database, extract basic info from filename
            metadata = {
                "app_name": os.path.splitext(filename)[0],
                "category": "Unknown",
                "operating_system": "Unknown",
                "supplier": "Unknown",
                "manufacturer": "Unknown",
                "version": "Unknown",
                "binary_type": "Unknown"
            }
        
        response = {
            "metadata": metadata,
            "sbom_data": data
        }
        
        return jsonify(response)
    except json.JSONDecodeError as e:
        return jsonify({"error": f"Invalid JSON in SBOM file: {str(e)}", "filename": filename}), 500
    except Exception as e:
        return jsonify({"error": f"Error loading SBOM: {str(e)}", "filename": filename}), 500

# Upload SBOM with metadata
@app.route('/api/upload', methods=['POST'])
def upload_sbom():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    metadata = request.form
    original_filename = file.filename
    
    # Use app_name in the filename if provided, otherwise use original name
    app_name = metadata.get('app_name')
    if app_name:
        # Create filename based on app_name (ensure it has .json extension)
        base_name = app_name.lower().replace(' ', '_')
        if original_filename.lower().endswith('.json'):
            filename = f"{base_name}.json"
        else:
            filename = f"{base_name}_sbom.json"
    else:
        filename = original_filename
    
    # Check if file already exists in database
    if SBOM.query.filter_by(filename=filename).first():
        return jsonify({"error": f"File with name {filename} already exists"}), 400

    # Ensure directories exist with appropriate permissions
    try:
        # Create main SBOM directory
        os.makedirs(SBOM_DIR, exist_ok=True)
        os.chmod(SBOM_DIR, 0o777)  # Full permissions
        
        # Create dataset directory 
        os.makedirs(DATASET_DIR, exist_ok=True)
        os.chmod(DATASET_DIR, 0o777)  # Full permissions
    except Exception as e:
        print(f"Warning: Could not set permissions on directories: {e}")

    # Path to save in main SBOM directory
    sbom_dir_path = os.path.join(SBOM_DIR, filename)
    
    # Save to SBOM_DIR
    try:
        file.save(sbom_dir_path)
    except Exception as e:
        return jsonify({"error": f"Could not save file to main directory: {str(e)}"}), 500

    # Process SBOM to count components and licenses
    components, unique_licenses = process_sbom_file(sbom_dir_path)

    # Add to database
    new_sbom = SBOM(
        filename=filename,
        app_name=app_name or os.path.splitext(filename)[0],
        category=metadata.get('category'),
        operating_system=metadata.get('operating_system'),
        app_binary_type=metadata.get('app_binary_type', 'desktop'),
        supplier=metadata.get('supplier'),
        manufacturer=metadata.get('manufacturer'),
        version=metadata.get('version'),
        cost=float(metadata.get('cost') or 0),
        description=metadata.get('description', ''),
        total_components=components,
        unique_licenses=unique_licenses
    )

    db.session.add(new_sbom)
    db.session.commit()

    # Now try to copy to dataset directory
    dataset_saved = False
    dataset_dir_path = os.path.join(DATASET_DIR, filename)
    
    try:
        # Directly copy the file instead of opening/writing
        import shutil
        shutil.copy2(sbom_dir_path, dataset_dir_path)
        dataset_saved = True
    except Exception as e:
        print(f"Warning: Could not save to dataset directory: {e}")
    
    # Prepare response message
    message = f"{filename} uploaded successfully with metadata"
    if dataset_saved:
        message += " and added to dataset"
    else:
        message += " (Note: Only saved to main directory)"

    return jsonify({
        "message": message,
        "sbom_id": new_sbom.id,
        "filename": filename,
        "dataset_saved": dataset_saved
    }), 200

# Auto-generate SBOM from uploaded executable using Syft
@app.route('/api/generate-sbom', methods=['POST'])
def generate_sbom():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No executable file uploaded"}), 400

    original_name = file.filename
    ext = os.path.splitext(original_name)[1]
    unique_name = f"{uuid.uuid4().hex}{ext}"
    exe_path = os.path.join(UPLOAD_DIR, unique_name)

    file.save(exe_path)

    # Generate SBOM using Syft
    sbom_filename = f"{os.path.splitext(original_name)[0]}_sbom.json"
    sbom_path = os.path.join(SBOM_DIR, sbom_filename)

    try:
        result = subprocess.run(
            ["syft", exe_path, "-o", "cyclonedx-json", "-q"],
            capture_output=True,
            text=True,
            check=True
        )
        with open(sbom_path, 'w') as f:
            f.write(result.stdout)

        # Process SBOM for metadata
        components, unique_licenses = process_sbom_file(sbom_path)

        # Save in DB
        new_sbom = SBOM(
            filename=sbom_filename,
            app_name=request.form.get("app_name") or os.path.splitext(original_name)[0],
            category=request.form.get("category"),
            operating_system=request.form.get("operating_system"),
            app_binary_type=request.form.get("app_binary_type", "desktop"),
            supplier=request.form.get("supplier"),
            manufacturer=request.form.get("manufacturer"),
            version=request.form.get("version"),
            cost=float(request.form.get("cost") or 0),
            description=request.form.get("description", ''),
            total_components=components,
            unique_licenses=unique_licenses
        )
        db.session.add(new_sbom)
        db.session.commit()

        return jsonify({
            "message": f"SBOM generated successfully for {original_name}", 
            "sbom_id": new_sbom.id,
            "filename": sbom_filename
        }), 200

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Syft error: {e.stderr}"}), 500
    except Exception as e:
        return jsonify({"error": f"Error: {str(e)}"}), 500
    finally:
        if os.path.exists(exe_path):
            os.remove(exe_path)

# Search for components within a specific SBOM file
@app.route('/api/search-components', methods=['POST'])
def search_components():
    data = request.get_json()
    keyword = data.get('keyword')
    filename = data.get('sbom_file')

    if not keyword or not filename:
        return jsonify({"error": "Keyword and SBOM filename required"}), 400

    # Check if file exists in SBOM_DIR
    file_path = os.path.join(SBOM_DIR, filename)
    if not os.path.exists(file_path):
        # Try DATASET_DIR if not found in SBOM_DIR
        file_path = os.path.join(DATASET_DIR, filename)
        if not os.path.exists(file_path):
            return jsonify({"error": "SBOM not found"}), 404

    with open(file_path, 'r') as f:
        sbom_data = json.load(f)

    # Extract components based on SBOM format
    components = extract_components_from_sbom(sbom_data)
    
    # Search for keyword in components
    results = []
    keyword_lower = keyword.lower()
    for component in components:
        if keyword_lower in json.dumps(component).lower():
            results.append(component)

    return jsonify({
        "filename": filename,
        "total_matches": len(results),
        "results": results
    })

# Compare two SBOMs
@app.route('/api/compare', methods=['POST'])
def compare_sboms():
    data = request.get_json()
    sbom1 = data.get('sbom1')
    sbom2 = data.get('sbom2')

    if not sbom1 or not sbom2:
        return jsonify({"error": "Two SBOM filenames are required"}), 400

    # Process first SBOM
    sbom1_data, sbom1_meta = get_sbom_data_and_meta(sbom1)
    if not sbom1_data:
        return jsonify({"error": f"SBOM {sbom1} not found"}), 404

    # Process second SBOM
    sbom2_data, sbom2_meta = get_sbom_data_and_meta(sbom2)
    if not sbom2_data:
        return jsonify({"error": f"SBOM {sbom2} not found"}), 404

    # Extract components
    components1 = extract_components_from_sbom(sbom1_data)
    components2 = extract_components_from_sbom(sbom2_data)

    # Create component maps for efficient comparison
    comp_map1 = {get_component_key(comp): comp for comp in components1}
    comp_map2 = {get_component_key(comp): comp for comp in components2}
    
    # Find components in both SBOMs
    common_keys = set(comp_map1.keys()) & set(comp_map2.keys())
    common_components = [comp_map1[key] for key in common_keys]
    
    # Find components only in first SBOM
    only_in_first_keys = set(comp_map1.keys()) - set(comp_map2.keys())
    only_in_first = [comp_map1[key] for key in only_in_first_keys]
    
    # Find components only in second SBOM
    only_in_second_keys = set(comp_map2.keys()) - set(comp_map1.keys())
    only_in_second = [comp_map2[key] for key in only_in_second_keys]
    
    # Calculate license distribution
    licenses1 = count_licenses(components1)
    licenses2 = count_licenses(components2)
    
    comparison_stats = {
        "common_component_count": len(common_components),
        "only_in_first_count": len(only_in_first),
        "only_in_second_count": len(only_in_second),
        "first_total_components": len(components1),
        "second_total_components": len(components2),
        "similarity_percentage": round(len(common_components) / (len(components1) + len(components2) - len(common_components)) * 100, 2) if components1 and components2 else 0
    }

    return jsonify({
        "sbom1_meta": sbom1_meta,
        "sbom2_meta": sbom2_meta,
        "comparison_stats": comparison_stats,
        "common_components": common_components[:100],  # Limit to 100 for performance
        "only_in_first": only_in_first[:100],
        "only_in_second": only_in_second[:100],
        "sbom1_licenses": licenses1,
        "sbom2_licenses": licenses2
    })

# Search for SBOMs by various criteria including fuzzy matching
@app.route('/api/search', methods=['GET'])
def search_sboms():
    # Get search parameters
    name = request.args.get('name', '')
    category = request.args.get('category', '')
    operating_system = request.args.get('os', '')
    binary_type = request.args.get('binary_type', '')
    supplier = request.args.get('supplier', '')
    manufacturer = request.args.get('manufacturer', '')
    
    # Build query
    query = SBOM.query
    
    # Apply filters
    if name:
        query = query.filter(or_(
            SBOM.app_name.ilike(f'%{name}%'),
            SBOM.filename.ilike(f'%{name}%')
        ))
    
    if category:
        query = query.filter(SBOM.category.ilike(f'%{category}%'))
    
    if operating_system:
        query = query.filter(SBOM.operating_system.ilike(f'%{operating_system}%'))
    
    if binary_type:
        query = query.filter(SBOM.app_binary_type.ilike(f'%{binary_type}%'))
    
    if supplier:
        query = query.filter(SBOM.supplier.ilike(f'%{supplier}%'))
    
    if manufacturer:
        query = query.filter(SBOM.manufacturer.ilike(f'%{manufacturer}%'))
    
    # Execute query
    sboms = query.all()
    
    # Format results
    results = []
    for sbom in sboms:
        results.append({
            "id": sbom.id,
            "filename": sbom.filename,
            "app_name": sbom.app_name,
            "category": sbom.category,
            "operating_system": sbom.operating_system,
            "supplier": sbom.supplier,
            "manufacturer": sbom.manufacturer,
            "version": sbom.version,
            "binary_type": sbom.app_binary_type,
            "total_components": sbom.total_components,
            "unique_licenses": sbom.unique_licenses
        })
    
    return jsonify({
        "count": len(results),
        "results": results
    })

# Get statistical information about SBOMs
@app.route('/api/statistics', methods=['GET'])
def sbom_statistics():
    # Get filter parameters
    category = request.args.get('category')
    operating_system = request.args.get('os')
    supplier = request.args.get('supplier')
    manufacturer = request.args.get('manufacturer')
    binary_type = request.args.get('binary_type')
    
    # Build query with filters
    query = SBOM.query
    
    if category:
        query = query.filter(SBOM.category.ilike(f'%{category}%'))
    
    if operating_system:
        query = query.filter(SBOM.operating_system.ilike(f'%{operating_system}%'))
    
    if supplier:
        query = query.filter(SBOM.supplier.ilike(f'%{supplier}%'))
    
    if manufacturer:
        query = query.filter(SBOM.manufacturer.ilike(f'%{manufacturer}%'))
    
    if binary_type:
        query = query.filter(SBOM.app_binary_type.ilike(f'%{binary_type}%'))
    
    # Execute query
    sboms = query.all()
    
    stats = {
        "total_sboms": len(sboms),
        "total_components": sum(sbom.total_components for sbom in sboms),
        "average_components_per_sbom": round(sum(sbom.total_components for sbom in sboms) / len(sboms), 2) if sboms else 0,
        "average_unique_licenses": round(sum(sbom.unique_licenses for sbom in sboms) / len(sboms), 2) if sboms else 0
    }
    
    # Collect additional statistics
    os_counter = Counter()
    category_counter = Counter()
    binary_type_counter = Counter()
    supplier_counter = Counter()
    manufacturer_counter = Counter()
    license_counter = Counter()

    # Process each SBOM
    for sbom in sboms:
        os_name = sbom.operating_system or "Unknown"
        os_counter[os_name] += 1

        cat = sbom.category or "Unknown"
        category_counter[cat] += 1
        
        bin_type = sbom.app_binary_type or "Unknown"
        binary_type_counter[bin_type] += 1
        
        sup = sbom.supplier or "Unknown"
        supplier_counter[sup] += 1
        
        manu = sbom.manufacturer or "Unknown"
        manufacturer_counter[manu] += 1
        
        # Get license information from file
        try:
            file_path = get_sbom_file_path(sbom.filename)
            if file_path:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                components = extract_components_from_sbom(data)
                
                for component in components:
                    for license_info in get_component_licenses(component):
                        license_counter[license_info] += 1
        except Exception as e:
            print(f"Error getting license info for {sbom.filename}: {e}")
    
    # Add distribution data to statistics
    stats["os_distribution"] = dict(os_counter.most_common())
    stats["category_distribution"] = dict(category_counter.most_common())
    stats["binary_type_distribution"] = dict(binary_type_counter.most_common())
    stats["supplier_distribution"] = dict(supplier_counter.most_common(10))
    stats["manufacturer_distribution"] = dict(manufacturer_counter.most_common(10))
    stats["license_distribution"] = dict(license_counter.most_common(10))

    return jsonify(stats)

# Get platform-specific statistics
@app.route('/api/platform-stats', methods=['GET'])
def platform_statistics():
    platforms = {
        "Windows": SBOM.query.filter(SBOM.operating_system.ilike('%windows%')).all(),
        "Linux": SBOM.query.filter(SBOM.operating_system.ilike('%linux%')).all(),
        "macOS": SBOM.query.filter(SBOM.operating_system.ilike('%mac%')).all(),
        "Android": SBOM.query.filter(SBOM.operating_system.ilike('%android%')).all(),
        "iOS": SBOM.query.filter(SBOM.operating_system.ilike('%ios%')).all()
    }
    
    results = {}
    
    for platform_name, sboms in platforms.items():
        if not sboms:
            results[platform_name] = {"count": 0}
            continue
        
        platform_stats = {
            "count": len(sboms),
            "total_components": sum(sbom.total_components for sbom in sboms),
            "average_components": round(sum(sbom.total_components for sbom in sboms) / len(sboms), 2),
            "binary_types": {}
        }
        
        # Count binary types
        binary_counter = Counter()
        for sbom in sboms:
            binary_counter[sbom.app_binary_type or "Unknown"] += 1
        
        platform_stats["binary_types"] = dict(binary_counter.most_common())
        
        # Count most common licenses
        license_counter = Counter()
        for sbom in sboms:
            try:
                file_path = get_sbom_file_path(sbom.filename)
                if file_path:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                    components = extract_components_from_sbom(data)
                    
                    for component in components:
                        for license_info in get_component_licenses(component):
                            license_counter[license_info] += 1
            except Exception as e:
                print(f"Error getting license info: {e}")
        
        platform_stats["top_licenses"] = dict(license_counter.most_common(5))
        results[platform_name] = platform_stats
    
    return jsonify(results)

# Diagnostic endpoint for listing all SBOMs with file existence check
@app.route('/api/diagnostics/sboms', methods=['GET'])
def diagnostic_sboms():
    sboms = SBOM.query.all()
    results = []
    
    for sbom in sboms:
        # Check if file exists
        sbom_file = sbom.filename
        file_in_sbom_dir = os.path.exists(os.path.join(SBOM_DIR, sbom_file))
        file_in_dataset_dir = os.path.exists(os.path.join(DATASET_DIR, sbom_file))
        
        results.append({
            "id": sbom.id,
            "filename": sbom.filename,
            "app_name": sbom.app_name,
            "operating_system": sbom.operating_system,
            "category": sbom.category,
            "file_exists_in_sbom_dir": file_in_sbom_dir,
            "file_exists_in_dataset_dir": file_in_dataset_dir,
            "file_exists": file_in_sbom_dir or file_in_dataset_dir
        })
    
    return jsonify({
        "count": len(results),
        "sboms": results
    })

# Get autocomplete suggestions for search fields
@app.route('/api/suggestions', methods=['GET'])
def get_suggestions():
    field = request.args.get('field')
    prefix = request.args.get('prefix', '')
    
    if not field or field not in ['app_name', 'category', 'operating_system', 
                                 'supplier', 'manufacturer', 'app_binary_type']:
        return jsonify({"error": "Invalid or missing field parameter"}), 400
    
    # Map field names to model attributes
    field_map = {
        'app_name': SBOM.app_name,
        'category': SBOM.category,
        'operating_system': SBOM.operating_system,
        'supplier': SBOM.supplier, 
        'manufacturer': SBOM.manufacturer,
        'app_binary_type': SBOM.app_binary_type
    }
    
    # Build and execute query
    attr = field_map[field]
    query = db.session.query(attr).distinct()
    
    if prefix:
        query = query.filter(attr.ilike(f'{prefix}%'))
    
    # Get results
    values = [r[0] for r in query.all() if r[0] is not None and r[0] != '']
    
    return jsonify({"suggestions": values})

# Helper functions
def process_sbom_file(file_path):
    """Process SBOM file to count components and unique licenses"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        components = extract_components_from_sbom(data)
        unique_licenses = set()
        
        for component in components:
            for license_info in get_component_licenses(component):
                unique_licenses.add(license_info)
        
        return len(components), len(unique_licenses)
    except Exception as e:
        print(f"Error processing SBOM file {file_path}: {e}")
        return 0, 0

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

def get_component_key(component):
    """Generate a unique key for a component for comparison"""
    name = component.get("name", "")
    version = component.get("version", "")
    purl = component.get("purl", "")
    
    if purl:
        return purl
    
    if name and version:
        return f"{name}@{version}"
    
    return str(component)

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

def count_licenses(components):
    """Count license occurrences in components"""
    license_counter = Counter()
    
    for component in components:
        for license_info in get_component_licenses(component):
            license_counter[license_info] += 1
    
    return dict(license_counter.most_common(10))

def get_sbom_data_and_meta(filename):
    """Get SBOM data and metadata for a file"""
    # Get the file path
    file_path = get_sbom_file_path(filename)
    if not file_path:
        return None, None
    
    # Load SBOM data
    try:
        with open(file_path, 'r') as f:
            sbom_data = json.load(f)
    except Exception:
        return None, None
    
    # Get metadata
    sbom = SBOM.query.filter_by(filename=filename).first()
    metadata = {
        "filename": filename,
        "app_name": sbom.app_name if sbom else os.path.splitext(filename)[0],
        "category": sbom.category if sbom else "Unknown",
        "operating_system": sbom.operating_system if sbom else "Unknown",
        "app_binary_type": sbom.app_binary_type if sbom else "Unknown",
        "supplier": sbom.supplier if sbom else "Unknown",
        "manufacturer": sbom.manufacturer if sbom else "Unknown",
        "version": sbom.version if sbom else "Unknown"
    }
    
    return sbom_data, metadata

def get_sbom_file_path(filename):
    """Find SBOM file in different directories"""
    # Check SBOM_DIR
    file_path = os.path.join(SBOM_DIR, filename)
    if os.path.exists(file_path):
        return file_path
    
    # Check DATASET_DIR
    file_path = os.path.join(DATASET_DIR, filename)
    if os.path.exists(file_path):
        return file_path
    
    return None

# Initialize DB
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)
