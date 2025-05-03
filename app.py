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

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# File storage path
SBOM_DIR = "./sbom_files/"
UPLOAD_DIR = "./uploads/"
os.makedirs(SBOM_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sboms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# SBOM Database Model
class SBOM(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), unique=True, nullable=False)
    category = db.Column(db.String(50))
    operating_system = db.Column(db.String(50))
    supplier = db.Column(db.String(100))
    version = db.Column(db.String(50))
    cost = db.Column(db.Float)
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

# Get specific SBOM file contents
@app.route('/api/sbom/<filename>', methods=['GET'])
def get_sbom(filename):
    file_path = os.path.join(SBOM_DIR, filename)
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    else:
        return jsonify({"error": "SBOM not found"}), 404

# Upload SBOM with metadata
@app.route('/api/upload', methods=['POST'])
def upload_sbom():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    metadata = request.form
    filename = file.filename
    file_path = os.path.join(SBOM_DIR, filename)

    if SBOM.query.filter_by(filename=filename).first():
        return jsonify({"error": "File already exists"}), 400

    file.save(file_path)

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

    return jsonify({"message": f"{filename} uploaded successfully with metadata"}), 200

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
    sbom_filename = f"{original_name}_sbom.json"
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

        return jsonify({"message": f"SBOM generated successfully for {original_name}"}), 200

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Syft error: {e.stderr}"}), 500
    finally:
        if os.path.exists(exe_path):
            os.remove(exe_path)

# Search for components in a given SBOM
@app.route('/api/search', methods=['POST'])
def search_sbom():
    data = request.get_json()
    keyword = data.get('keyword')
    filename = data.get('sbom_file')

    if not keyword or not filename:
        return jsonify({"error": "Keyword and SBOM filename required"}), 400

    path = os.path.join(SBOM_DIR, filename)
    if not os.path.exists(path):
        return jsonify({"error": "File not found"}), 404

    with open(path, 'r') as f:
        sbom_data = json.load(f)

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

    if not os.path.exists(path1) or not os.path.exists(path2):
        return jsonify({"error": "One or both files not found"}), 404

    with open(path1, 'r') as f1, open(path2, 'r') as f2:
        artifacts1 = json.load(f1).get("artifacts", [])
        artifacts2 = json.load(f2).get("artifacts", [])

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

    if not os.path.exists(path1) or not os.path.exists(path2):
        return jsonify({"error": "One or both files not found"}), 404

    # Extract text from both SBOMs
    try:
        with open(path1, 'r') as f1, open(path2, 'r') as f2:
            content1 = json.dumps(json.load(f1))
            content2 = json.dumps(json.load(f2))
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON in one or both files"}), 400

    # Extract significant terms (words that aren't common JSON syntax)
    def extract_terms(content):
        # Remove common JSON syntax
        text = re.sub(r'[{}\[\],:""]', ' ', content)
        # Split into words, lowercase, and remove short terms
        words = [word.lower() for word in text.split() if len(word) > 3]
        return Counter(words)

    terms1 = extract_terms(content1)
    terms2 = extract_terms(content2)
    
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

@app.route('/api/statistics', methods=['GET'])
def sbom_statistics():
    stats = {
        "total_sboms": 0,
        "total_packages": 0,
        "license_distribution": {},
        "supplier_distribution": {},
        "os_distribution": {},
    }

    sboms = SBOM.query.all()
    stats["total_sboms"] = len(sboms)

    license_counter = Counter()
    supplier_counter = Counter()
    os_counter = Counter()
    total_packages = 0

    for sbom in sboms:
        path = os.path.join(SBOM_DIR, sbom.filename)
        if not os.path.exists(path):
            continue

        try:
            with open(path, 'r') as f:
                data = json.load(f)
                artifacts = data.get("artifacts", [])
                total_packages += len(artifacts)

                for item in artifacts:
                    # Handle licenses
                    licenses = item.get("licenses", [])
                    for l in licenses:
                        lic = l.get("license", {}).get("id", "Unknown")
                        license_counter[lic] += 1

                    # Handle supplier
                    supplier = item.get("supplier", "Unknown")
                    supplier_counter[supplier] += 1

        except Exception as e:
            print(f"Error reading {sbom.filename}: {e}")
            continue

        # OS from metadata
        os_name = sbom.operating_system or "Unknown"
        os_counter[os_name] += 1

    stats["total_packages"] = total_packages
    stats["license_distribution"] = dict(license_counter.most_common(10))
    stats["supplier_distribution"] = dict(supplier_counter.most_common(10))
    stats["os_distribution"] = dict(os_counter)

    return jsonify(stats)

# Initialize DB
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)

