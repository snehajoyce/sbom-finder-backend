from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json

app = Flask(__name__)
CORS(app)

SBOM_DIR = "./sbom_files/"
os.makedirs(SBOM_DIR, exist_ok=True)

@app.route('/')
def home():
    return "Welcome to SBOM Finder Backend!"

@app.route('/api/sboms', methods=['GET'])
def list_sboms():
    sbom_files = os.listdir(SBOM_DIR)
    return jsonify(sbom_files)

@app.route('/api/sbom/<filename>', methods=['GET'])
def get_sbom(filename):
    file_path = os.path.join(SBOM_DIR, filename)
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    else:
        return jsonify({"error": "SBOM not found"}), 404

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

@app.route('/api/upload', methods=['POST'])
def upload_sbom():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    file_path = os.path.join(SBOM_DIR, file.filename)
    file.save(file_path)
    return jsonify({"message": f"{file.filename} uploaded successfully"}), 200

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

if __name__ == '__main__':
    app.run(debug=True, port=5001)


