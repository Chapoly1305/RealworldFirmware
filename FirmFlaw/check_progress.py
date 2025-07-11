#!/usr/bin/env python3
"""
Check progress of parallel processing from checkpoint file
"""
import json
import sys
from pathlib import Path
from datetime import datetime

def format_time(iso_time):
    """Format ISO time to readable format"""
    try:
        dt = datetime.fromisoformat(iso_time)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return iso_time

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 check_progress.py <project_name>")
        print("\nAvailable checkpoints:")
        for cp in Path('.').glob('checkpoint_*.json'):
            print(f"  - {cp.name}")
        sys.exit(1)
    
    project_name = sys.argv[1]
    checkpoint_file = f"checkpoint_{project_name}.json"
    
    if not Path(checkpoint_file).exists():
        print(f"Checkpoint file not found: {checkpoint_file}")
        sys.exit(1)
    
    with open(checkpoint_file, 'r') as f:
        data = json.load(f)
    
    # Display metadata
    print(f"\n{'='*60}")
    print(f"Project: {data['metadata']['project_name']}")
    print(f"Source: {data['metadata']['source_dir']}")
    print(f"Started: {format_time(data['metadata']['start_time'])}")
    print(f"Total files: {data['metadata']['total_files']}")
    print(f"{'='*60}\n")
    
    # Count file statuses
    statuses = {}
    for file_id, info in data['files'].items():
        status = info.get('status', 'unknown')
        statuses[status] = statuses.get(status, 0) + 1
    
    print("File Status Summary:")
    for status, count in sorted(statuses.items()):
        percentage = (count / data['metadata']['total_files'] * 100) if data['metadata']['total_files'] > 0 else 0
        print(f"  {status:20s}: {count:5d} ({percentage:5.1f}%)")
    
    # Display stage completion
    print(f"\n{'='*60}")
    print("Processing Stages:")
    stages = [
        ('analysis_complete', 'Binary Analysis'),
        ('fid_complete', 'FID Creation'),
        ('matchdb_complete', 'Database Creation'),
        ('merge_complete', 'Database Merge')
    ]
    
    for stage_key, stage_name in stages:
        status = "✓ Complete" if data['stages'].get(stage_key) else "○ Pending"
        print(f"  {stage_name:20s}: {status}")
    
    # Show recent activity
    print(f"\n{'='*60}")
    print("Recent Activity (last 10 files):")
    
    # Get files sorted by timestamp
    recent_files = []
    for file_id, info in data['files'].items():
        if 'timestamp' in info:
            recent_files.append((info['timestamp'], file_id, info))
    
    recent_files.sort(reverse=True)
    
    for timestamp, file_id, info in recent_files[:10]:
        file_path = info.get('file_path', 'unknown')
        status = info.get('status', 'unknown')
        time_str = format_time(timestamp)
        
        # Truncate long paths
        if len(file_path) > 50:
            file_path = "..." + file_path[-47:]
        
        print(f"  {time_str} | {status:15s} | {file_path}")
    
    # Show failed files if any
    failed_files = [(fid, info) for fid, info in data['files'].items() 
                    if info.get('status') == 'failed']
    
    if failed_files:
        print(f"\n{'='*60}")
        print(f"Failed Files ({len(failed_files)} total):")
        for file_id, info in failed_files[:10]:  # Show first 10
            file_path = info.get('file_path', 'unknown')
            error = info.get('error', 'No error message')
            print(f"  File: {file_path}")
            print(f"  Error: {error}\n")
        
        if len(failed_files) > 10:
            print(f"  ... and {len(failed_files) - 10} more failed files")
    
    print(f"\n{'='*60}")
    
    # Suggest next action
    if not data['stages'].get('analysis_complete'):
        pending = sum(1 for f in data['files'].values() 
                     if f.get('status') != 'analysis_complete')
        if pending > 0:
            print(f"\nTo resume processing {pending} remaining files:")
            print(f"  python3 run_parallel_complete.py {project_name} <source_dir> --resume")
    elif not data['stages'].get('merge_complete'):
        print("\nAnalysis complete. Continue with FID/database creation:")
        print(f"  python3 run_parallel_complete.py {project_name} <source_dir> --resume")
    else:
        print("\nAll processing complete!")
        print(f"  Database: ./db/binfunc_{project_name}.db")
        print(f"  FID files: ./fidb/{project_name}_fid_*.fidb")

if __name__ == "__main__":
    main()