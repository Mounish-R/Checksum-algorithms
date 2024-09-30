import hashlib
import os

def compute_sha256(file_path):
    """Compute the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def compute_md5(file_path):
    """Compute the MD5 hash of a file."""
    md5_hash = hashlib.md5()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    return md5_hash.hexdigest()

def process_file(file_path):
    """Compute and save SHA-256 and MD5 hashes to a metadata file."""
    sha256 = compute_sha256(file_path)
    md5 = compute_md5(file_path)

    # Save to metadata file
    metadata_filename = f"{file_path}.meta"
    with open(metadata_filename, 'w') as meta_file:
        meta_file.write(f"SHA256: {sha256}\n")
        meta_file.write(f"MD5: {md5}\n")

    print(f"Processed {file_path} - SHA256: {sha256}, MD5: {md5}")

def validate_file(file_path):
    """Validate the file against its saved SHA-256 and MD5 hashes."""
    metadata_filename = f"{file_path}.meta"

    if not os.path.exists(metadata_filename):
        print("No metadata found. Please process the file first.")
        return

    with open(metadata_filename, 'r') as meta_file:
        expected_sha256 = meta_file.readline().split(': ')[1].strip()
        expected_md5 = meta_file.readline().split(': ')[1].strip()

    actual_sha256 = compute_sha256(file_path)
    actual_md5 = compute_md5(file_path)

    if actual_sha256 != expected_sha256:
        print(f"SHA256 mismatch for {file_path}: expected {expected_sha256}, got {actual_sha256}")
    elif actual_md5 != expected_md5:
        print(f"MD5 mismatch for {file_path}: expected {expected_md5}, got {actual_md5}")
    else:
        print("File validation successful.")

if __name__ == "__main__":
    action = input("Enter action (process/validate): ").strip().lower()
    filename = input("Enter filename: ").strip()

    if action == "process":
        process_file(filename)
    elif action == "validate":
        validate_file(filename)
    else:
        print("Invalid action. Please enter 'process' or 'validate'.")
