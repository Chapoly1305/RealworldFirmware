#!/usr/bin/env python3
"""
Search all FID files against a target project
Iterates through all .fidb files in subdirectories to find matches
"""
import os
import sys
import json
import time
import logging
import argparse
import subprocess
from pathlib import Path
from collections import defaultdict

def setup_logging(project_name):
    """Setup logging configuration"""
    log_time = time.strftime("%Y-%m-%d_%H:%M:%S")
    log_dir = Path('./logs')
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / f'FidSearchAll_{project_name}_{log_time}.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return log_time

def find_all_fidb_files(fidb_root):
    """Find all .fidb files in the directory tree"""
    fidb_files = []
    fidb_root = Path(fidb_root)
    
    if not fidb_root.exists():
        logging.error(f"FID directory {fidb_root} does not exist")
        return fidb_files
    
    # Find all .fidb files
    for fidb_file in fidb_root.rglob("*.fidb"):
        # Extract relative path for organization
        rel_path = fidb_file.relative_to(fidb_root)
        parent_dir = rel_path.parent.name if rel_path.parent != Path('.') else 'root'
        fidb_files.append({
            'path': fidb_file,
            'name': fidb_file.stem,
            'parent': parent_dir,
            'rel_path': str(rel_path)
        })
    
    return fidb_files

def search_with_fid(project_path, project_name, fid_info):
    """Run FID search with a specific FID file"""
    cmd = [
        sys.executable,
        "Fid.py",
        "-s",
        str(project_path),
        project_name,
        str(fid_info['rel_path']).replace('.fidb', '')  # FID name without extension
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            # Parse results from output or check result files
            result_file = Path(f"./res/functionID_{project_name}_{fid_info['name']}_*.json")
            matching_files = list(Path('./res').glob(f"functionID_{project_name}_{fid_info['name']}_*.json"))
            
            if matching_files:
                # Get the most recent result file
                latest_file = max(matching_files, key=lambda f: f.stat().st_mtime)
                with open(latest_file, 'r') as f:
                    matches = json.load(f)
                return len(matches), matches
            else:
                return 0, {}
        else:
            logging.error(f"FID search failed for {fid_info['name']}: {result.stderr}")
            return 0, {}
    except Exception as e:
        logging.error(f"Error searching with FID {fid_info['name']}: {e}")
        return 0, {}

def main():
    parser = argparse.ArgumentParser(description="Search all FID files against a target project")
    parser.add_argument("project_path", type=Path, help="Path to Ghidra projects")
    parser.add_argument("project_name", help="Name of target project to search")
    parser.add_argument("fidb_path", type=Path, help="Root directory containing FID files")
    args = parser.parse_args()
    
    log_time = setup_logging(args.project_name)
    
    logging.info(f"Starting FID search for project: {args.project_name}")
    logging.info(f"FID directory: {args.fidb_path}")
    
    # Find all FID files
    fidb_files = find_all_fidb_files(args.fidb_path)
    logging.info(f"Found {len(fidb_files)} FID files")
    
    # Group by parent directory
    by_parent = defaultdict(list)
    for fid in fidb_files:
        by_parent[fid['parent']].append(fid)
    
    # Results storage
    all_results = {}
    summary_by_version = {}
    
    # Search with each FID file
    for parent, fids in by_parent.items():
        logging.info(f"\nSearching with FIDs from: {parent}")
        version_matches = 0
        version_details = {}
        
        for fid_info in fids:
            logging.info(f"  Searching with: {fid_info['name']}")
            match_count, matches = search_with_fid(args.project_path, args.project_name, fid_info)
            
            if match_count > 0:
                version_matches += match_count
                version_details[fid_info['name']] = {
                    'count': match_count,
                    'matches': matches
                }
                logging.info(f"    Found {match_count} matches")
        
        summary_by_version[parent] = {
            'total_matches': version_matches,
            'fid_count': len(fids),
            'details': version_details
        }
        
        all_results[parent] = version_details
    
    # Save comprehensive results
    output_file = Path(f"./res/FidSearchAll_{args.project_name}_{log_time}.json")
    with open(output_file, 'w') as f:
        json.dump({
            'project': args.project_name,
            'timestamp': log_time,
            'summary': summary_by_version,
            'detailed_results': all_results
        }, f, indent=2)
    
    # Save summary CSV
    csv_file = Path(f"./res/FidSearchAll_{args.project_name}_{log_time}_summary.csv")
    with open(csv_file, 'w') as f:
        f.write("Version,Total_Matches,FID_Files_Checked\n")
        for version, data in summary_by_version.items():
            f.write(f"{version},{data['total_matches']},{data['fid_count']}\n")
    
    # Log summary
    logging.info("\n=== SUMMARY ===")
    best_version = max(summary_by_version.items(), key=lambda x: x[1]['total_matches'])
    logging.info(f"Best matching version: {best_version[0]} with {best_version[1]['total_matches']} matches")
    
    for version, data in sorted(summary_by_version.items(), key=lambda x: x[1]['total_matches'], reverse=True):
        logging.info(f"{version}: {data['total_matches']} matches from {data['fid_count']} FID files")
    
    logging.info(f"\nResults saved to: {output_file}")
    logging.info(f"Summary saved to: {csv_file}")

if __name__ == "__main__":
    main()