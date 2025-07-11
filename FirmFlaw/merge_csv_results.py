#!/usr/bin/env python3
import os
import csv
from collections import defaultdict
from pathlib import Path
from utils.sample_folders import get_current_res_dir, load_current_context

def get_res_directory():
    """
    Get the appropriate res directory based on analysis context.
    Uses sample-specific folder if target analysis context is set, otherwise uses legacy ./res
    """
    try:
        # Try to get current sample res directory (for target analysis)
        return get_current_res_dir()
    except ValueError:
        # Fallback to legacy res directory (for regular processing)
        return Path('./res')

def merge_matchdb_csv():
    """Merge all MatchDB CSV files into one"""
    merged_data = defaultdict(int)
    
    # Read all MatchDB CSV files from temp directory
    for i in range(9):  # 0 through 8
        filename = f"./temp_csv/MatchDB_firmware_match_file_{i}.csv"
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    program = row['Program'].strip()
                    # Handle column name with space
                    functions_key = 'Functions' if 'Functions' in row else ' Functions'
                    functions = int(row[functions_key].strip())
                    merged_data[program] += functions
    
    # Write merged data
    res_dir = get_res_directory()
    with open(res_dir / 'MatchDB_merged.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Program', 'Functions'])
        for program, functions in sorted(merged_data.items()):
            writer.writerow([program, functions])
    
    print(f"Merged {len(merged_data)} entries into MatchDB_merged.csv")

def merge_func_num_csv():
    """Merge all func_num CSV files into one"""
    merged_data = defaultdict(lambda: [0, 0, 0, 0])  # handlers, functions, size, time
    
    # Read all func_num CSV files from temp directory
    for i in range(9):  # 0 through 8
        filename = f"./temp_csv/func_num_firmware_match_file_{i}.csv"
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Handle column names with spaces
                    program = row.get('Program', row.get(' Program', '')).strip()
                    handlers = int(row.get('Handlers', row.get(' Handlers', '0')).strip())
                    functions = int(row.get('Functions', row.get(' Functions', '0')).strip())
                    size = row.get('Size', row.get(' Size', '')).strip()
                    if size and size.lower() != 'none':
                        size = int(size)
                    else:
                        size = 0
                    analysis_time = int(row.get('AnalysisTime', row.get(' AnalysisTime', '0')).strip())
                    
                    # Aggregate data
                    merged_data[program][0] += handlers
                    merged_data[program][1] += functions
                    merged_data[program][2] = max(merged_data[program][2], size)  # Use max size
                    merged_data[program][3] += analysis_time
    
    # Write merged data
    res_dir = get_res_directory()
    with open(res_dir / 'func_num_merged.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Program', 'Handlers', 'Functions', 'Size', 'AnalysisTime'])
        for program, data in sorted(merged_data.items()):
            writer.writerow([program] + data)
    
    print(f"Merged {len(merged_data)} entries into func_num_merged.csv")

def remove_fragments():
    """Remove the fragment CSV files after merging"""
    removed_count = 0
    
    # Remove MatchDB fragments from temp directory
    for i in range(9):
        filename = f"./temp_csv/MatchDB_firmware_match_file_{i}.csv"
        if os.path.exists(filename):
            os.remove(filename)
            removed_count += 1
    
    # Remove func_num fragments from temp directory
    for i in range(9):
        filename = f"./temp_csv/func_num_firmware_match_file_{i}.csv"
        if os.path.exists(filename):
            os.remove(filename)
            removed_count += 1
    
    print(f"Removed {removed_count} fragment CSV files")
    
    # Remove temp directory if empty
    import shutil
    if os.path.exists('./temp_csv') and not os.listdir('./temp_csv'):
        shutil.rmtree('./temp_csv')
        print("Removed empty temp_csv directory")

if __name__ == "__main__":
    import sys
    
    # Try to load analysis context (for target analysis)
    load_current_context()
    
    print("Merging CSV files...")
    merge_matchdb_csv()
    merge_func_num_csv()
    
    # Check for command-line argument or ask
    if len(sys.argv) > 1 and sys.argv[1] == '-y':
        remove_fragments()
    else:
        try:
            response = input("Remove fragment CSV files? (y/n): ")
            if response.lower() == 'y':
                remove_fragments()
        except EOFError:
            print("Skipping fragment removal (no input)")
    
    print("Done!")