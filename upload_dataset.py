import os
import requests
import time

# Define your dataset directory (handle space in folder name)
DATASET_DIR = os.path.join(os.getcwd(), "SBOM Dataset")
UPLOAD_URL = "http://localhost:5001/api/upload"

def extract_metadata_from_filename(filename):
    # Example: acme-firefox-windows-v1.0.json
    parts = filename.lower().replace(".json", "").split("-")
    return {
        "supplier": parts[0] if len(parts) > 0 else "Unknown",
        "category": parts[1] if len(parts) > 1 else "Application",
        "operating_system": parts[2] if len(parts) > 2 else "Unknown",
        "version": parts[3] if len(parts) > 3 else "1.0",
        "cost": "0"
    }

def upload_all_sboms():
    if not os.path.exists(DATASET_DIR):
        print("Dataset directory not found.")
        return

    files_uploaded = 0

    for filename in os.listdir(DATASET_DIR):
        if filename.endswith(".json"):
            file_path = os.path.join(DATASET_DIR, filename)
            metadata = extract_metadata_from_filename(filename)

            with open(file_path, 'rb') as f:
                files = {'file': (filename, f)}
                response = requests.post(UPLOAD_URL, data=metadata, files=files)

                if response.status_code == 200:
                    print(f"✅ Uploaded: {filename}")
                    files_uploaded += 1
                else:
                    print(f"❌ Failed: {filename} | {response.text}")

            time.sleep(0.5)  # Avoid server overload

    print(f"\nUpload complete. {files_uploaded} files uploaded successfully.")

if __name__ == "__main__":
    upload_all_sboms()
