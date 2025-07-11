#!/usr/bin/env python3
"""
Script to count nrf versions from SimMaxMatch JSON file.
Extracts version numbers from the 'program' field and provides statistics.

Usage:
    python count_nrf_versions.py <SimMaxMatch_json_file>

Example:
    python count_nrf_versions.py SimMaxMatch_binfunc_target_extracted_firmware.db_binfunc_firmware_match.db_2025-07-11_06:01:33.json
"""

import json
import sys
import re
from collections import Counter
from pathlib import Path


def extract_nrf_version(program_name):
    """
    Extract nrf version from program name.
    
    Args:
        program_name (str): Program name like "nrf_2.8.0_libCredentials.FabricTable.cpp.o"
    
    Returns:
        str or None: Version string like "2.8.0" or None if not nrf
    """
    match = re.match(r'nrf_(\d+\.\d+\.\d+)_', program_name)
    return match.group(1) if match else None


def count_nrf_versions(json_file_path):
    """
    Count nrf versions from SimMaxMatch JSON file.
    
    Args:
        json_file_path (str): Path to the SimMaxMatch JSON file
    
    Returns:
        dict: Statistics about nrf versions
    """
    try:
        with open(json_file_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File {json_file_path} not found")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {json_file_path}: {e}")
        return None
    
    version_counter = Counter()
    total_functions = 0
    nrf_functions = 0
    non_nrf_programs = set()
    
    # Process each firmware file
    for firmware_name, functions in data.items():
        print(f"Processing firmware: {firmware_name}")
        
        for func_id, func_data in functions.items():
            total_functions += 1
            program_name = func_data.get('program', '')
            
            version = extract_nrf_version(program_name)
            if version:
                version_counter[version] += 1
                nrf_functions += 1
            else:
                # Track non-nrf programs for analysis
                if program_name and not program_name.startswith('nrf_'):
                    non_nrf_programs.add(program_name)
    
    return {
        'version_counts': version_counter,
        'total_functions': total_functions,
        'nrf_functions': nrf_functions,
        'non_nrf_functions': total_functions - nrf_functions,
        'non_nrf_programs': non_nrf_programs
    }


def print_statistics(stats):
    """Print formatted statistics."""
    if not stats:
        return
    
    print("\n" + "="*60)
    print("NRF VERSION ANALYSIS RESULTS")
    print("="*60)
    
    print(f"\nTotal functions analyzed: {stats['total_functions']}")
    print(f"Functions with nrf versions: {stats['nrf_functions']}")
    print(f"Functions without nrf versions: {stats['non_nrf_functions']}")
    
    if stats['total_functions'] > 0:
        print(f"nrf coverage: {stats['nrf_functions']/stats['total_functions']*100:.1f}%")
    else:
        print("nrf coverage: No functions to analyze (0.0%)")
    
    print(f"\nNRF VERSION COUNTS:")
    print("-" * 30)
    
    # Sort versions for better readability
    sorted_versions = sorted(stats['version_counts'].items(), 
                           key=lambda x: tuple(map(int, x[0].split('.'))))
    
    for version, count in sorted_versions:
        percentage = count / stats['nrf_functions'] * 100 if stats['nrf_functions'] > 0 else 0
        print(f"  nrf_{version:<8} {count:>6} functions ({percentage:5.1f}%)")
    
    print(f"\nTOTAL NRF VERSIONS FOUND: {len(stats['version_counts'])}")
    
    # Show non-nrf programs if any (for debugging)
    if stats['non_nrf_programs']:
        print(f"\nNon-nrf programs found: {len(stats['non_nrf_programs'])}")
        if len(stats['non_nrf_programs']) <= 10:
            for program in sorted(stats['non_nrf_programs']):
                print(f"  - {program}")
        else:
            print("  (Too many to display, first 10:)")
            for program in sorted(stats['non_nrf_programs'])[:10]:
                print(f"  - {program}")


def main():
    """Main function."""
    if len(sys.argv) != 2:
        print("Usage: python count_nrf_versions.py <SimMaxMatch_json_file>")
        print("\nExample:")
        print("  python count_nrf_versions.py SimMaxMatch_binfunc_target_extracted_firmware.db_binfunc_firmware_match.db_2025-07-11_06:01:33.json")
        sys.exit(1)
    
    json_file = sys.argv[1]
    
    # Check if file exists
    if not Path(json_file).exists():
        print(f"Error: File '{json_file}' does not exist")
        sys.exit(1)
    
    print(f"Analyzing nrf versions from: {json_file}")
    
    stats = count_nrf_versions(json_file)
    print_statistics(stats)


if __name__ == "__main__":
    main()