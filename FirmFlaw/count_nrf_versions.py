#!/usr/bin/env python3
"""
Script to count nrf versions from multiple JSON files in a directory.
Extracts version numbers from the 'program' field and outputs statistics as CSV.

Usage:
    python count_nrf_versions.py <directory_path> <output_csv_file>

Example:
    python count_nrf_versions.py /path/to/results/res analysis_results.csv
"""

import json
import sys
import re
import csv
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


def extract_sample_name(json_file_name):
    """
    Extract sample file name from SimMaxMatch JSON file name.
    
    Args:
        json_file_name (str): JSON file name like "SimMaxMatch_binfunc_target_firmwares_ota_99409_53.db_binfunc_firmware_match.db_07_11_23_45.json"
    
    Returns:
        str: Sample file name like "ota_99409.bin" or the original filename if pattern not found
    """
    match = re.search(r'ota_(\d+)_', json_file_name)
    if match:
        return f"ota_{match.group(1)}.bin"
    return json_file_name  # fallback to original filename


def count_nrf_versions(json_file_path):
    """
    Count nrf versions from a JSON file.
    
    Args:
        json_file_path (str): Path to the JSON file
    
    Returns:
        dict: Statistics about nrf versions for this file
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
    
    file_name = Path(json_file_path).name
    sample_name = extract_sample_name(file_name)
    
    return {
        'file_name': file_name,
        'sample_name': sample_name,
        'version_counts': version_counter,
        'total_functions': total_functions,
        'nrf_functions': nrf_functions,
        'non_nrf_functions': total_functions - nrf_functions,
        'unique_versions': len(version_counter),
        'most_common_version': version_counter.most_common(1)[0] if version_counter else (None, 0)
    }


def analyze_directory(directory_path):
    """
    Analyze all SimMaxMatch JSON files in a directory.
    
    Args:
        directory_path (str): Path to directory containing JSON files
    
    Returns:
        list: List of statistics for each file
    """
    results = []
    # Only process SimMaxMatch files
    json_files = list(Path(directory_path).glob('SimMaxMatch_*.json'))
    
    print(f"Found {len(json_files)} SimMaxMatch JSON files to analyze")
    
    for i, json_file in enumerate(json_files, 1):
        print(f"Processing file {i}/{len(json_files)}: {json_file.name}")
        stats = count_nrf_versions(str(json_file))
        if stats:
            results.append(stats)
    
    return results


def write_csv_results(results, output_file):
    """
    Write analysis results to CSV file.
    
    Args:
        results (list): List of statistics for each file
        output_file (str): Path to output CSV file
    """
    # Collect all unique versions across all files
    all_versions = set()
    for result in results:
        all_versions.update(result['version_counts'].keys())
    
    # Sort versions
    sorted_versions = sorted(all_versions, key=lambda x: tuple(map(int, x.split('.'))) if x else (0, 0, 0))
    
    # Prepare CSV headers
    headers = ['File Name', 'Sample Name', 'Total Functions', 'NRF Functions', 'Non-NRF Functions', 
               'NRF Coverage %', 'Unique Versions', 'Most Common Version', 'Most Common Count']
    
    # Add columns for each version
    for version in sorted_versions:
        headers.append(f'nrf_{version}')
    
    # Write CSV
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for result in results:
            row = [
                result['file_name'],
                result['sample_name'],
                result['total_functions'],
                result['nrf_functions'],
                result['non_nrf_functions'],
                f"{result['nrf_functions']/result['total_functions']*100:.1f}" if result['total_functions'] > 0 else "0.0",
                result['unique_versions'],
                result['most_common_version'][0] if result['most_common_version'][0] else 'N/A',
                result['most_common_version'][1]
            ]
            
            # Add count for each version
            for version in sorted_versions:
                row.append(result['version_counts'].get(version, 0))
            
            writer.writerow(row)
    
    # Also write a summary CSV with aggregated data
    summary_file = output_file.replace('.csv', '_summary.csv')
    write_summary_csv(results, summary_file, sorted_versions)


def write_summary_csv(results, summary_file, sorted_versions):
    """
    Write summary statistics to CSV file.
    
    Args:
        results (list): List of statistics for each file
        summary_file (str): Path to summary CSV file
        sorted_versions (list): Sorted list of version strings
    """
    # Aggregate statistics
    total_files = len(results)
    total_functions = sum(r['total_functions'] for r in results)
    total_nrf_functions = sum(r['nrf_functions'] for r in results)
    total_non_nrf_functions = sum(r['non_nrf_functions'] for r in results)
    
    # Aggregate version counts
    version_totals = Counter()
    for result in results:
        for version, count in result['version_counts'].items():
            version_totals[version] += count
    
    # Write summary
    with open(summary_file, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write summary statistics
        writer.writerow(['Summary Statistics'])
        writer.writerow(['Metric', 'Value'])
        writer.writerow(['Total Files Analyzed', total_files])
        writer.writerow(['Total Functions', total_functions])
        writer.writerow(['Total NRF Functions', total_nrf_functions])
        writer.writerow(['Total Non-NRF Functions', total_non_nrf_functions])
        writer.writerow(['Overall NRF Coverage %', f"{total_nrf_functions/total_functions*100:.1f}" if total_functions > 0 else "0.0"])
        writer.writerow([])
        
        # Write version distribution
        writer.writerow(['Version Distribution'])
        writer.writerow(['Version', 'Total Count', 'Percentage'])
        for version in sorted_versions:
            count = version_totals.get(version, 0)
            percentage = count / total_nrf_functions * 100 if total_nrf_functions > 0 else 0
            writer.writerow([f'nrf_{version}', count, f'{percentage:.1f}'])
    
    print(f"\nSummary written to: {summary_file}")


def main():
    """Main function."""
    if len(sys.argv) != 3:
        print("Usage: python count_nrf_versions.py <directory_path> <output_csv_file>")
        print("\nExample:")
        print("  python count_nrf_versions.py /path/to/results/res analysis_results.csv")
        sys.exit(1)
    
    directory_path = sys.argv[1]
    output_file = sys.argv[2]
    
    # Check if directory exists
    if not Path(directory_path).exists() or not Path(directory_path).is_dir():
        print(f"Error: Directory '{directory_path}' does not exist or is not a directory")
        sys.exit(1)
    
    print(f"Analyzing JSON files in: {directory_path}")
    
    # Analyze all files
    results = analyze_directory(directory_path)
    
    if not results:
        print("No valid JSON files found or analyzed")
        sys.exit(1)
    
    # Write results to CSV
    write_csv_results(results, output_file)
    print(f"\nResults written to: {output_file}")
    
    # Print summary
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)
    print(f"Files analyzed: {len(results)}")
    print(f"Total functions: {sum(r['total_functions'] for r in results)}")
    print(f"Total NRF functions: {sum(r['nrf_functions'] for r in results)}")


if __name__ == "__main__":
    main()