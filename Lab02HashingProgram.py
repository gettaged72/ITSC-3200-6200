import os
import hashlib
import json
import sys

HASH_TABLE_FILE = "hash_table.json"
ALGO_NAME = "sha256"

def norm_path(p: str) -> str:
    return os.path.normpath(os.path.abspath(p))

def hash_file(file_path):
#Calculates the cryptographic hash of a file’s contents
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error hashing file {file_path}: {e}")
        return None

def traverse_directory(directory):
#Navigates the directory and hashes files within it.
    hash_table = {}
    directory = norm_path(directory)

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = norm_path(os.path.join(root, file))

            # Avoid hashing the hash table file itself if it's inside the directory
            if os.path.basename(file_path) == HASH_TABLE_FILE:
                continue

            file_hash = hash_file(file_path)
            if file_hash:
                hash_table[file_path] = file_hash

    return hash_table

def generate_table():
    #Generates a hash table and saves it to JSON.
    directory = input("Enter the directory path to hash files: ").strip()
    if not os.path.isdir(directory):
        print("Invalid directory path.")
        return

    directory = norm_path(directory)
    files_hashes = traverse_directory(directory)

    data = {
        "base_dir": directory,
        "algo": ALGO_NAME,
        "files": files_hashes
    }

    with open(HASH_TABLE_FILE, 'w') as json_file:
        json.dump(data, json_file, indent=4)

    print("Hash table generated.")

def validate_hash():
    #Validates current directory files against stored hashes.
    if not os.path.exists(HASH_TABLE_FILE):
        print("No hash table found. Please generate a hash table first.")
        return

    with open(HASH_TABLE_FILE, 'r') as json_file:
        data = json.load(json_file)

    stored_dir = data.get("base_dir", "")
    stored_files = data.get("files", {})

    directory = input("Enter the directory path to verify hashes: ").strip()
    if not os.path.isdir(directory):
        print("Invalid directory path.")
        return

    directory = norm_path(directory)

    # Optional: warn if verifying a different directory than originally hashed
    if stored_dir and directory != norm_path(stored_dir):
        print(f"Warning: hash table was generated for {stored_dir}, but you are verifying {directory}.")

    current_hashes = traverse_directory(directory)

    # Bonus helper: hash -> old_path map (for rename detection)
    old_hash_to_path = {}
    for p, h in stored_files.items():
        old_hash_to_path.setdefault(h, p)

    # Check stored files: valid/invalid/deleted
    for file_path, stored_hash in stored_files.items():
        if file_path in current_hashes:
            current_hash = current_hashes[file_path]
            if current_hash == stored_hash:
                print(f"{file_path} hash is valid.")
            else:
                print(f"{file_path} hash is invalid.")
        else:
            print(f"{file_path} has been deleted.")

    # Check new files (and detect rename if bonus)
    for file_path, new_hash in current_hashes.items():
        if file_path not in stored_files:
            # BONUS: rename detection by hash match
            if new_hash in old_hash_to_path and old_hash_to_path[new_hash] not in current_hashes:
                old_path = old_hash_to_path[new_hash]
                print(f"File name change detected, {old_path} has been renamed to {file_path}.")
                # Update table: remove old path, add new path
                stored_files.pop(old_path, None)
                stored_files[file_path] = new_hash
            else:
                print(f"{file_path} has been added.")

    # Save updates if rename detection changed the table
    data["files"] = stored_files
    with open(HASH_TABLE_FILE, 'w') as json_file:
        json.dump(data, json_file, indent=4)

def main():
    while True:
        print("\nSelect an option:")
        print("1. Generate a new hash table")
        print("2. Verify hashes")
        print("3. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            generate_table()
        elif choice == '2':
            validate_hash()
        elif choice == '3':
            print("Exiting program.")
            sys.exit()
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
