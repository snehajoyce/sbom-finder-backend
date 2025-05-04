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
import tempfile
from google.cloud import storage

# Check if running in Cloud Run
RUNNING_IN_CLOUD_RUN = os.environ.get('K_SERVICE') is not None

# Initialize Flask app
app = Flask(__name__)
CORS(app, origins=[
    "https://sbom-frontend-6zbf.vercel.app",
    "https://sbom-frontend-6zbf-git-main-sneha-joyces-projects.vercel.app",
    "https://sbom-frontend-6zbf-dnll0fe15-sneha-joyces-projects.vercel.app"
])

# Storage setup
SBOM_DIR = "./sbom_files/"
UPLOAD_DIR = "./uploads/"
DATASET_DIR = "./sbom_files/SBOM/"
os.makedirs(SBOM_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DATASET_DIR, exist_ok=True)

# Cloud Storage configuration
BUCKET_NAME = os.environ.get('BUCKET_NAME', 'sbom-finder-storage')

# Setup cloud storage if running in Cloud Run
if RUNNING_IN_CLOUD_RUN:
    storage_client = storage.Client()
    try:
        bucket = storage_client.get_bucket(BUCKET_NAME)
    except Exception as e:
        print(f"Warning: Could not access bucket {BUCKET_NAME}: {e}")

# Database configuration
SQLITE_PATH = os.environ.get('SQLITE_PATH', 'sboms.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{SQLITE_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

def init_db():
    """Initializes the database and creates tables if they don't exist."""
    with app.app_context():
        # Check if tables exist (optional but good practice)
        # inspector = db.inspect(db.engine)
        # if not inspector.has_table('sbom'):
        #     print("Creating database tables...")
        #     db.create_all()
        # else:
        #     print("Database tables already exist.")
        # Simpler approach: just call create_all(), it's safe.
        print("Ensuring database tables exist...")
        db.create_all()
        print("Database tables checked/created.")

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
    file_path = os.path.join(SBOM_DIR, filename)
    
    # Use our abstracted file operations
    if not file_exists(file_path):
        return jsonify({"error": "SBOM not found"}), 404
    
    try:
        content = load_file(file_path)
        if content:
            data = json.loads(content)
            return jsonify(data)
        else:
            return jsonify({"error": "Failed to load SBOM content"}), 500
    except Exception as e:
        return jsonify({"error": f"Error loading SBOM: {str(e)}"}), 500

# Helper functions for file operations that work in both environments
def save_file(file_object, file_path):
    if RUNNING_IN_CLOUD_RUN:
        # Strip leading './' for cloud storage
        blob_name = file_path.replace('./', '')
        blob = bucket.blob(blob_name)
        
        # For files with content already in memory
        if hasattr(file_object, 'read'):
            content = file_object.read()
            # Reset file pointer if it's a file-like object
            if hasattr(file_object, 'seek'):
                file_object.seek(0)
            
            if isinstance(content, bytes):
                blob.upload_from_string(content, content_type='application/json')
            else:
                blob.upload_from_string(content)
        else:
            # Assume file_object is string content
            blob.upload_from_string(file_object)
    else:
        # For local storage
        if hasattr(file_object, 'save'):
            file_object.save(file_path)
        else:
            with open(file_path, 'w') as f:
                f.write(file_object)

def load_file(file_path):
    if RUNNING_IN_CLOUD_RUN:
        blob_name = file_path.replace('./', '')
        blob = bucket.blob(blob_name)
        
        if not blob.exists():
            return None
            
        return blob.download_as_text()
    else:
        if not os.path.exists(file_path):
            return None
            
        with open(file_path, 'r') as f:
            return f.read()

def file_exists(file_path):
    if RUNNING_IN_CLOUD_RUN:
        blob_name = file_path.replace('./', '')
        blob = bucket.blob(blob_name)
        return blob.exists()
    else:
        return os.path.exists(file_path)

# Upload SBOM with metadata
@app.route('/api/upload', methods=['POST'])
def upload_sbom():
    try:
        file = request.files.get('file')
        if not file:
            return jsonify({"error": "No file uploaded"}), 400

        metadata = request.form
        filename = file.filename
        file_path = os.path.join(SBOM_DIR, filename)

        if SBOM.query.filter_by(filename=filename).first():
            return jsonify({"error": "File already exists"}), 400
        
        # Save file using our abstraction
        try:
            print(f"Uploading file {filename} to {file_path}")
            save_file(file, file_path)
            
            # Also save to SBOM directory for dataset
            dataset_path = os.path.join(SBOM_DIR, "SBOM", filename)
            print(f"Also saving to dataset at {dataset_path}")
            file.seek(0)  # Reset file pointer
            save_file(file, dataset_path)
            
            print(f"File {filename} uploaded successfully")
        except Exception as e:
            print(f"Error saving file: {str(e)}")
            return jsonify({"error": f"Failed to save file: {str(e)}"}), 500

        try:
            # Add to database
            new_sbom = SBOM(
                filename=filename,
                category=metadata.get('category'),
                operating_system=metadata.get('operating_system'),
                supplier=metadata.get('supplier'),
                version=metadata.get('version'),
                cost=float(metadata.get('cost') or 0)
            )

            db.session.add(new_sbom)
            db.session.commit()
            print(f"Added {filename} to database")
        except Exception as e:
            print(f"Database error: {str(e)}")
            return jsonify({"error": f"Database error: {str(e)}"}), 500

        return jsonify({
            "message": f"{filename} uploaded successfully with metadata",
            "filename": filename,
            "cloud_storage": RUNNING_IN_CLOUD_RUN
        }), 200
    except Exception as e:
        print(f"Unexpected error in upload: {str(e)}")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

# Auto-generate SBOM from uploaded executable using Syft
@app.route('/api/generate-sbom', methods=['POST'])
def generate_sbom():
    try:
        file = request.files.get('file')
        if not file:
            return jsonify({"error": "No executable file uploaded"}), 400

        original_name = file.filename
        ext = os.path.splitext(original_name)[1]
        unique_name = f"{uuid.uuid4().hex}{ext}"
        exe_path = os.path.join(UPLOAD_DIR, unique_name)

        # Save executable file
        try:
            print(f"Saving executable to {exe_path}")
            save_file(file, exe_path)
        except Exception as e:
            print(f"Error saving executable: {str(e)}")
            return jsonify({"error": f"Failed to save executable: {str(e)}"}), 500

        # Generate SBOM filename
        sbom_filename = f"{original_name}_sbom.json"
        sbom_path = os.path.join(SBOM_DIR, sbom_filename)

        try:
            # Generate SBOM using Syft - only works in local environment
            if not RUNNING_IN_CLOUD_RUN:
                print("Generating SBOM with Syft")
                result = subprocess.run(
                    ["syft", exe_path, "-o", "cyclonedx-json", "-q"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                # Save SBOM content
                save_file(result.stdout, sbom_path)
            else:
                # In Cloud Run, we can't run Syft directly
                # For demo purposes, create a simple placeholder SBOM
                print("Running in Cloud Run - creating placeholder SBOM")
                placeholder_sbom = {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "serialNumber": f"urn:uuid:{uuid.uuid4()}",
                    "version": 1,
                    "metadata": {
                        "timestamp": datetime.now().isoformat(),
                        "component": {
                            "name": original_name,
                            "type": "application"
                        }
                    },
                    "components": [],
                    "artifacts": []
                }
                save_file(json.dumps(placeholder_sbom, indent=2), sbom_path)

            # Log in DB
            new_sbom = SBOM(
                filename=sbom_filename,
                category=request.form.get("category"),
                operating_system=request.form.get("operating_system"),
                supplier=request.form.get("supplier"),
                version=request.form.get("version"),
                cost=float(request.form.get("cost") or 0)
            )
            db.session.add(new_sbom)
            db.session.commit()
            print(f"Added {sbom_filename} to database")

            # Also save to SBOM directory for dataset
            dataset_path = os.path.join(SBOM_DIR, "SBOM", sbom_filename)
            if file_exists(sbom_path):
                content = load_file(sbom_path)
                if content:
                    save_file(content, dataset_path)
                    print(f"Also saved to dataset at {dataset_path}")

            return jsonify({
                "message": f"SBOM generated successfully for {original_name}",
                "sbom_filename": sbom_filename,
                "original_name": original_name,
                "cloud_run": RUNNING_IN_CLOUD_RUN
            }), 200

        except subprocess.CalledProcessError as e:
            print(f"Syft error: {e.stderr}")
            return jsonify({"error": f"Syft error: {e.stderr}"}), 500
        except Exception as e:
            print(f"Error generating SBOM: {str(e)}")
            return jsonify({"error": f"Error generating SBOM: {str(e)}"}), 500
        finally:
            # Clean up the uploaded executable file
            if file_exists(exe_path):
                try:
                    if not RUNNING_IN_CLOUD_RUN:
                        os.remove(exe_path)
                    print(f"Cleaned up {exe_path}")
                except Exception as e:
                    print(f"Warning: Could not remove temporary file: {str(e)}")
    except Exception as e:
        print(f"Unexpected error in generate-sbom: {str(e)}")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

# Search for components in a given SBOM
@app.route('/api/search', methods=['POST'])
def search_sbom():
    data = request.get_json()
    keyword = data.get('keyword')
    filename = data.get('sbom_file')

    if not keyword or not filename:
        return jsonify({"error": "Keyword and SBOM filename required"}), 400

    path = os.path.join(SBOM_DIR, filename)
    if not file_exists(path):
        return jsonify({"error": "File not found"}), 404

    content = load_file(path)
    if not content:
        return jsonify({"error": "Failed to load SBOM content"}), 500
    
    sbom_data = json.loads(content)
    artifacts = sbom_data.get("artifacts", [])
    results = [a for a in artifacts if keyword.lower() in json.dumps(a).lower()]

    return jsonify({"results": results})

# Compare two SBOMs
@app.route('/api/compare', methods=['POST'])
def compare_sboms():
    data = request.get_json()
    sbom1 = data.get('sbom1')
    sbom2 = data.get('sbom2')

    path1 = os.path.join(SBOM_DIR, sbom1)
    path2 = os.path.join(SBOM_DIR, sbom2)

    if not file_exists(path1) or not file_exists(path2):
        return jsonify({"error": "One or both files not found"}), 404

    content1 = load_file(path1)
    content2 = load_file(path2)
    
    if not content1 or not content2:
        return jsonify({"error": "Failed to load one or both SBOM files"}), 500
    
    artifacts1 = json.loads(content1).get("artifacts", [])
    artifacts2 = json.loads(content2).get("artifacts", [])

    set1 = {json.dumps(a, sort_keys=True) for a in artifacts1}
    set2 = {json.dumps(a, sort_keys=True) for a in artifacts2}

    only_in_1 = [json.loads(item) for item in set1 - set2]
    only_in_2 = [json.loads(item) for item in set2 - set1]

    return jsonify({
        "only_in_first": only_in_1,
        "only_in_second": only_in_2
    })

# Compare two SBOMs based on common terms, ignoring schema
@app.route('/api/compare-terms', methods=['POST'])
def compare_sbom_terms():
    data = request.get_json()
    sbom1 = data.get('sbom1')
    sbom2 = data.get('sbom2')

    path1 = os.path.join(SBOM_DIR, sbom1)
    path2 = os.path.join(SBOM_DIR, sbom2)

    if not file_exists(path1) or not file_exists(path2):
        return jsonify({"error": "One or both files not found"}), 404

    # Extract text from both SBOMs
    try:
        content1 = load_file(path1)
        content2 = load_file(path2)
        
        if not content1 or not content2:
            return jsonify({"error": "Failed to load one or both SBOM files"}), 500
            
        content1_json = json.dumps(json.loads(content1))
        content2_json = json.dumps(json.loads(content2))
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON in one or both files"}), 400

    # Extract significant terms (words that aren't common JSON syntax)
    def extract_terms(content):
        # Remove common JSON syntax
        text = re.sub(r'[{}\[\],:""]', ' ', content)
        # Split into words, lowercase, and remove short terms
        words = [word.lower() for word in text.split() if len(word) > 3]
        return Counter(words)

    terms1 = extract_terms(content1_json)
    terms2 = extract_terms(content2_json)
    
    # Find common terms and their frequencies
    common_terms = {}
    for term in set(terms1.keys()) & set(terms2.keys()):
        common_terms[term] = {
            "file1_count": terms1[term],
            "file2_count": terms2[term],
            "total": terms1[term] + terms2[term]
        }
    
    # Find unique terms in each file
    unique_to_file1 = {term: terms1[term] for term in terms1 if term not in terms2}
    unique_to_file2 = {term: terms2[term] for term in terms2 if term not in terms1}
    
    # Sort results by frequency
    sorted_common = sorted(
        common_terms.items(), 
        key=lambda x: x[1]["total"], 
        reverse=True
    )[:50]  # Limit to top 50 common terms
    
    sorted_unique1 = sorted(
        unique_to_file1.items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:25]  # Limit to top 25 unique terms
    
    sorted_unique2 = sorted(
        unique_to_file2.items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:25]  # Limit to top 25 unique terms
    
    return jsonify({
        "common_terms": dict(sorted_common),
        "unique_to_first": dict(sorted_unique1),
        "unique_to_second": dict(sorted_unique2),
        "similarity_score": len(common_terms) / (len(terms1) + len(terms2) - len(common_terms)) if (len(terms1) + len(terms2) - len(common_terms)) > 0 else 0
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
init_db() # Call the function to ensure tables are created on startup

if __name__ == '__main__':
    # The init_db() call above handles the create_all()
    app.run(debug=True, port=5001)
