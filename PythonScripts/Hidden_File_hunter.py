import json
import sys
import csv
from typing import List, Dict, Tuple
from pathlib import Path

def parse_file(path: str) -> List[Dict]:
    """Read and parse JSON lines from file."""
    try:
        with open(path) as f:
            return [json.loads(line) for line in f]
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error processing file {path}: {str(e)}")
        sys.exit(1)

def is_hidden_folder(entry: Dict) -> bool:
    """Check if entry is a hidden folder."""
    attributes = entry.get("FileAttributes", [])
    return "HIDDEN" in attributes and "DIRECTORY" in attributes

def is_hidden_file(entry: Dict) -> bool:
    """Check if entry is a hidden file (excluding system and temporary files)."""
    attributes = entry.get("FileAttributes", [])
    return ("HIDDEN" in attributes and 
            "DIRECTORY" not in attributes and 
            "TEMPORARY" not in attributes and 
            "SYSTEM" not in attributes)

def process_entries(entries: List[Dict]) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Process entries and return dictionaries of hidden files and folders with their paths."""
    hidden_files: Dict[str, str] = {}
    hidden_folders: Dict[str, str] = {}

    for entry in entries:
        filename = entry.get("Filename", "")
        file_path = entry.get("OSPath", "")
        
        if is_hidden_folder(entry):
            hidden_folders[filename] = file_path
        elif is_hidden_file(entry):
            hidden_files[filename] = file_path

    return hidden_folders, hidden_files

def write_to_csv(hidden_folders: Dict[str, str], hidden_files: Dict[str, str], output_file: str) -> None:
    """Write hidden files and folders to a CSV file."""
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Type', 'Name', 'Path'])
        
        for name, path in sorted(hidden_folders.items()):
            writer.writerow(['Folder', name, path])
        
        for name, path in sorted(hidden_files.items()):
            writer.writerow(['File', name, path])

def find_hidden_files(input_path: str) -> None:
    """Find hidden files and folders and save results to CSV."""
    entries = parse_file(input_path)
    hidden_folders, hidden_files = process_entries(entries)
    
    # Print results
    print("\nHidden folders found:")
    for name, path in sorted(hidden_folders.items()):
        print(f"  {name}: {path}")
    
    print("\nHidden files found:")
    for name, path in sorted(hidden_files.items()):
        print(f"  {name}: {path}")
    
    # Save to CSV
    output_file = Path(input_path).with_suffix('.csv')
    write_to_csv(hidden_folders, hidden_files, str(output_file))
    print(f"\nResults saved to: {output_file}")

def main() -> None:
    """Main entry point of the script."""
    args = sys.argv[1:]
    
    if len(args) == 2 and args[0] == "-f":
        find_hidden_files(args[1])
    else:
        print("Usage: python script.py -f <json_file_path>")
        sys.exit(1)

if __name__ == "__main__":
    main()
