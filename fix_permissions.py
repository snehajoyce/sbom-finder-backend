#!/usr/bin/env python3
import os
import stat
import sys

def fix_directory_permissions(directory):
    """
    Fix permissions for a directory and all its contents.
    """
    if not os.path.exists(directory):
        print(f"Creating directory: {directory}")
        os.makedirs(directory, exist_ok=True, mode=0o777)
    else:
        print(f"Setting permissions for: {directory}")
        try:
            # Set directory to be writable by everyone
            os.chmod(directory, 0o777)
        except PermissionError as e:
            print(f"Error setting permissions on {directory}: {e}")
            print("You may need to run this script with sudo")
            return False
    
    return True

def main():
    """
    Fix permissions for all SBOM directories.
    """
    print("SBOM Finder Backend - Permission Fixer")
    print("--------------------------------------")
    
    # Get base directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(base_dir)
    
    # Directories to fix
    directories = [
        "./sbom_files",
        "./sbom_files/SBOM",
        "./uploads",
        "./instance"
    ]
    
    success = True
    for directory in directories:
        if not fix_directory_permissions(directory):
            success = False
    
    if success:
        print("\nAll permissions fixed successfully!")
        print("\nYou should now be able to run the SBOM Finder backend and upload files.")
    else:
        print("\nThere were errors fixing permissions.")
        print("Try running this script with sudo, e.g.:")
        print("sudo python3 fix_permissions.py")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main()) 