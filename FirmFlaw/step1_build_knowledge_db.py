#!/usr/bin/env python3
"""
Step 1: Build Knowledge Database
Creates database and FID files from match_base directory.
Merges functionality from prepare.sh and database building part of run_parallel_complete.py
"""
import os
import sys
import time
import json
import shutil
import sqlite3
import subprocess
import multiprocessing as mp
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
import logging
import argparse

log_time = time.strftime("%m_%d_%H_%M")

class CheckpointManager:
    """Manages checkpoint file for tracking progress"""
    def __init__(self, checkpoint_file):
        self.checkpoint_file = Path(checkpoint_file)
        self.data = self.load()
    
    def load(self):
        """Load checkpoint data from file"""
        if self.checkpoint_file.exists():
            with open(self.checkpoint_file, 'r') as f:
                return json.load(f)
        else:
            return {
                'metadata': {
                    'start_time': datetime.now().isoformat(),
                    'project_name': '',
                    'source_dir': '',
                    'total_files': 0
                },
                'files': {},
                'stages': {
                    'analysis_complete': False,
                    'fid_complete': False,
                    'matchdb_complete': False,
                    'merge_complete': False
                }
            }
    
    def save(self):
        """Save checkpoint data to file"""
        with open(self.checkpoint_file, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def update_file_status(self, file_id, status, details=None):
        """Update status for a specific file"""
        if str(file_id) not in self.data['files']:
            self.data['files'][str(file_id)] = {}
        
        self.data['files'][str(file_id)]['status'] = status
        self.data['files'][str(file_id)]['timestamp'] = datetime.now().isoformat()
        
        if details:
            self.data['files'][str(file_id)].update(details)
        
        self.save()
    
    def get_file_status(self, file_id):
        """Get status for a specific file"""
        return self.data['files'].get(str(file_id), {}).get('status', 'pending')
    
    def get_pending_files(self, all_files):
        """Get list of files that haven't been processed"""
        pending = []
        for file_path, file_id in all_files:
            if self.get_file_status(file_id) != 'analysis_complete':
                pending.append((file_path, file_id))
        return pending
    
    def update_stage(self, stage, complete=True):
        """Update completion status of a stage"""
        self.data['stages'][stage] = complete
        self.save()
    
    def get_completed_projects(self):
        """Get list of successfully completed projects"""
        completed = []
        for file_id, info in self.data['files'].items():
            if info.get('status') == 'analysis_complete' and 'project_info' in info:
                completed.append(info['project_info'])
        return completed

def create_directories():
    """Create necessary directories (merged from prepare.sh)"""
    directories = ["./logs", "./res", "./db", "./fidb", "./ghidra_projects"]
    for dir_path in directories:
        Path(dir_path).mkdir(exist_ok=True)
        logging.info(f"Ensured directory exists: {dir_path}")

def setup_logging():
    """Setup logging configuration"""
    log_dir = Path('./logs')
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / f'step1_build_knowledge_db_{log_time}.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def analyze_single_file(file_info, checkpoint):
    """Analyze a single file in its own Ghidra project"""
    file_path, file_id, base_project_name = file_info
    
    # Check if already completed
    if checkpoint.get_file_status(file_id) == 'analysis_complete':
        logging.info(f"Skipping {file_path} (ID: {file_id}) - already completed")
        return checkpoint.data['files'][str(file_id)].get('project_info')
    
    # Update status to in_progress
    checkpoint.update_file_status(file_id, 'in_progress', {'file_path': str(file_path)})
    
    # Create unique project for this file
    project_location = Path("./ghidra_projects")
    project_location.mkdir(exist_ok=True)
    project_name = f"{base_project_name}_file_{file_id}"
    project_dir = project_location / project_name
    
    # Create temporary directory with just this file
    temp_dir = Path(f"./temp_analysis/{base_project_name}/temp_single_{file_id}")
    temp_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy single file preserving structure
    file_path_obj = Path(file_path)
    parent_folder = file_path_obj.parent.name
    original_name = file_path_obj.name
    
    # Include parent folder in filename to distinguish files with same name
    new_filename = f"{parent_folder}_{original_name}"
    dest_file = temp_dir / new_filename
    shutil.copy2(file_path, dest_file)
    
    # Run buildProject.py
    cmd = [
        sys.executable,
        "buildProject.py",
        str(project_location),
        project_name,
        str(temp_dir),
        "-s", "./utils/valid.py"
    ]
    
    try:
        logging.info(f"Starting analysis of {file_path} (ID: {file_id})")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Clean up temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        if result.returncode != 0:
            logging.error(f"Failed to analyze {file_path}: {result.stderr}")
            return None
            
        logging.info(f"Completed analysis of {file_path}")
        
        project_info = {
            'file_id': file_id,
            'file_path': str(file_path),
            'parent_folder': parent_folder,
            'project_dir': str(project_dir),
            'project_name': project_name,
            'success': True
        }
        
        # Update checkpoint with success
        checkpoint.update_file_status(file_id, 'analysis_complete', {
            'project_info': project_info
        })
        
        return project_info
        
    except Exception as e:
        logging.error(f"Error analyzing {file_path}: {e}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        # Update checkpoint with failure
        checkpoint.update_file_status(file_id, 'failed', {
            'error': str(e)
        })
        
        return None

def create_fid_single(proj_info, base_project_name, index):
    """Create FID for a single project"""
    if not proj_info or not proj_info['success']:
        return None
        
    # Convert project_dir back to Path if it's a string
    project_dir = Path(proj_info['project_dir']) if isinstance(proj_info['project_dir'], str) else proj_info['project_dir']
    
    # Extract filename without extension for FID name
    file_path = Path(proj_info['file_path'])
    file_stem = file_path.stem  # Gets filename without extension
    parent_folder = proj_info.get('parent_folder', '')
    
    # Create FID name and path
    if parent_folder:
        fid_dir = Path(f'./fidb/{parent_folder}')
        fid_dir.mkdir(parents=True, exist_ok=True)
        fid_name = f"{parent_folder}/{file_stem}"
    else:
        fid_name = file_stem
    
    cmd = [
        sys.executable,
        "Fid.py",
        "-c",
        str(project_dir.parent),                # Project location (parent dir)
        proj_info['project_name'],              # Project name
        fid_name                                # FID name with path
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            logging.info(f"Created FID for project {proj_info['project_name']} as {fid_name}")
            return {'fid_name': fid_name, 'parent_folder': parent_folder, 'file_stem': file_stem}
        else:
            logging.error(f"Failed to create FID for {proj_info['project_name']}: {result.stderr}")
            return None
    except Exception as e:
        logging.error(f"Error creating FID for {proj_info['project_name']}: {e}")
        return None

def create_fid_from_projects(project_info_list, base_project_name, checkpoint):
    """Create FID database from all individual projects in parallel"""
    logging.info(f"Creating FID database from {len(project_info_list)} projects")
    
    # Check if already completed
    if checkpoint.data['stages'].get('fid_complete'):
        logging.info("FID creation already completed, skipping")
        return []
    
    # We'll create a master FID by running Fid.py on each project
    # First, ensure fidb directory exists
    fidb_dir = Path('./fidb')
    fidb_dir.mkdir(exist_ok=True)
    
    # Use multiprocessing to create FIDs in parallel
    fid_files = []
    num_workers = mp.cpu_count()
    
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        # Submit all jobs
        future_to_info = {
            executor.submit(create_fid_single, proj_info, base_project_name, i): i 
            for i, proj_info in enumerate(project_info_list)
        }
        
        # Collect results
        completed = 0
        for future in as_completed(future_to_info):
            completed += 1
            if completed % 10 == 0:
                logging.info(f"FID Progress: {completed}/{len(project_info_list)} projects processed")
                
            try:
                result = future.result()
                if result:
                    fid_files.append(result)
            except Exception as e:
                index = future_to_info[future]
                logging.error(f"Failed to process FID for index {index}: {e}")
    
    logging.info(f"Created {len(fid_files)} FID files")
    checkpoint.update_stage('fid_complete', True)
    return fid_files

def run_matchdb_single(proj_info):
    """Run MatchDB on a single project"""
    if not proj_info or not proj_info['success']:
        return None
        
    # Convert project_dir back to Path if it's a string
    project_dir = Path(proj_info['project_dir']) if isinstance(proj_info['project_dir'], str) else proj_info['project_dir']
    
    cmd = [
        sys.executable,
        "MatchDB.py",
        str(project_dir.parent),
        proj_info['project_name']
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            db_path = Path(f"./db/binfunc_{proj_info['project_name']}.db")
            if db_path.exists():
                logging.info(f"Created database for {proj_info['project_name']}")
                return db_path
        else:
            logging.error(f"Failed to create database for {proj_info['project_name']}: {result.stderr}")
            return None
    except Exception as e:
        logging.error(f"Error creating database for {proj_info['project_name']}: {e}")
        return None

def run_matchdb_on_projects(project_info_list, base_project_name, checkpoint):
    """Run MatchDB on all projects to create SQLite databases in parallel"""
    logging.info(f"Creating SQLite databases from {len(project_info_list)} projects")
    
    # Check if already completed
    if checkpoint.data['stages'].get('matchdb_complete'):
        logging.info("MatchDB creation already completed, skipping")
        # Return list of existing database files
        db_files = []
        for proj_info in project_info_list:
            if proj_info and proj_info['success']:
                db_path = Path(f"./db/binfunc_{proj_info['project_name']}.db")
                if db_path.exists():
                    db_files.append(db_path)
        return db_files
    
    # Use multiprocessing to create databases in parallel
    db_files = []
    num_workers = mp.cpu_count()
    
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        # Submit all jobs
        future_to_info = {
            executor.submit(run_matchdb_single, proj_info): proj_info['project_name'] 
            for proj_info in project_info_list
            if proj_info and proj_info['success']
        }
        
        # Collect results
        completed = 0
        for future in as_completed(future_to_info):
            completed += 1
            if completed % 10 == 0:
                logging.info(f"MatchDB Progress: {completed}/{len(future_to_info)} projects processed")
                
            try:
                result = future.result()
                if result:
                    db_files.append(result)
            except Exception as e:
                project_name = future_to_info[future]
                logging.error(f"Failed to process database for {project_name}: {e}")
    
    checkpoint.update_stage('matchdb_complete', True)
    return db_files

def merge_databases(db_files, output_db):
    """Merge all individual databases into one"""
    logging.info(f"Merging {len(db_files)} databases into {output_db}")
    
    if not db_files:
        logging.error("No databases to merge")
        return 0
    
    # Create output database
    output_conn = sqlite3.connect(output_db)
    output_cursor = output_conn.cursor()
    
    # Get schema from first database
    first_conn = sqlite3.connect(db_files[0])
    
    # Copy table schema
    table_schema = first_conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL"
    ).fetchall()
    for schema in table_schema:
        output_cursor.execute(schema[0])
    
    # Copy index schema
    index_schema = first_conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
    ).fetchall()
    for schema in index_schema:
        output_cursor.execute(schema[0])
    
    first_conn.close()
    output_conn.commit()
    
    # Merge data from all databases
    total_functions = 0
    next_id = 1  # Start ID counter
    
    for db_file in db_files:
        try:
            conn = sqlite3.connect(db_file)
            # Select all columns except id
            data = conn.execute("""
                SELECT name, program, hash, numAddresses, mnemonics, 
                       block_num, edge_num, call_num, jump_num 
                FROM func_table
            """).fetchall()
            
            if data:
                # Insert with new IDs
                for row in data:
                    output_cursor.execute(
                        """INSERT INTO func_table 
                           (id, name, program, hash, numAddresses, mnemonics, 
                            block_num, edge_num, call_num, jump_num) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (next_id,) + row
                    )
                    next_id += 1
                
                total_functions += len(data)
                logging.info(f"Merged {len(data)} functions from {db_file.name}")
            conn.close()
        except Exception as e:
            logging.error(f"Error merging {db_file}: {e}")
    
    output_conn.commit()
    output_conn.close()
    
    logging.info(f"Successfully merged {total_functions} total functions")
    return total_functions

def cleanup_individual_databases(db_files):
    """Remove individual database files after merging"""
    for db_file in db_files:
        try:
            if db_file.exists():
                os.remove(db_file)
        except Exception as e:
            logging.error(f"Error removing {db_file}: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Step 1: Build knowledge database from firmware files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ./match_base                     # Build from match_base with default name
  %(prog)s ./match_base -n my_firmware      # Build with custom project name
  %(prog)s ./match_base --fresh             # Ignore checkpoint and start fresh
  %(prog)s ./match_base -w 8                # Use 8 workers for parallel processing
        """
    )
    
    parser.add_argument('source_dir', help='Directory containing firmware files to build database from')
    parser.add_argument('-n', '--name', default='firmware_match', 
                        help='Project name (default: firmware_match)')
    parser.add_argument('-w', '--workers', type=int, default=mp.cpu_count(),
                        help=f'Number of parallel workers (default: {mp.cpu_count()})')
    parser.add_argument('--fresh', action='store_true', 
                        help='Ignore existing checkpoint and start over')
    
    args = parser.parse_args()
    
    setup_logging()
    
    # Create necessary directories (functionality from prepare.sh)
    logging.info("Creating necessary directories...")
    create_directories()
    
    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        logging.error(f"Source directory {source_dir} does not exist")
        sys.exit(1)
    
    project_name = args.name
    num_workers = args.workers
    force_fresh = args.fresh
    
    # Create temp analysis directory
    temp_analysis_dir = Path(f"./temp_analysis/{project_name}")
    temp_analysis_dir.mkdir(parents=True, exist_ok=True)
    logging.info(f"Created temp analysis directory: {temp_analysis_dir}")
    
    # Initialize checkpoint
    checkpoint_file = f"./checkpoint_{project_name}.json"
    checkpoint_exists = Path(checkpoint_file).exists()
    
    # Auto-resume if checkpoint exists (unless --fresh is specified)
    if checkpoint_exists and force_fresh:
        logging.info(f"--fresh specified, removing existing checkpoint: {checkpoint_file}")
        os.remove(checkpoint_file)
        
        # Clean up old FID files (now in subdirectories)
        fidb_dir = Path('./fidb')
        if fidb_dir.exists():
            # Clean up old format FID files
            for fid_file in fidb_dir.glob(f"{project_name}_fid_*.fidb"):
                try:
                    os.remove(fid_file)
                    logging.info(f"Removed old FID file: {fid_file}")
                except Exception as e:
                    logging.warning(f"Could not remove FID file {fid_file}: {e}")
            
            # Clean up new format FID directories
            for subdir in fidb_dir.iterdir():
                if subdir.is_dir():
                    try:
                        shutil.rmtree(subdir)
                        logging.info(f"Removed FID directory: {subdir}")
                    except Exception as e:
                        logging.warning(f"Could not remove FID directory {subdir}: {e}")
        
        # Clean up old database files
        db_dir = Path('./db')
        if db_dir.exists():
            # Remove individual databases
            for db_file in db_dir.glob(f"binfunc_{project_name}_file_*.db"):
                try:
                    os.remove(db_file)
                    logging.info(f"Removed old database: {db_file}")
                except Exception as e:
                    logging.warning(f"Could not remove database {db_file}: {e}")
            
            # Remove merged database
            merged_db = db_dir / f"binfunc_{project_name}.db"
            if merged_db.exists():
                try:
                    os.remove(merged_db)
                    logging.info(f"Removed old merged database: {merged_db}")
                except Exception as e:
                    logging.warning(f"Could not remove merged database {merged_db}: {e}")
        
        checkpoint = CheckpointManager(checkpoint_file)
        resume = False
    elif checkpoint_exists:
        logging.info(f"Found existing checkpoint: {checkpoint_file}")
        checkpoint = CheckpointManager(checkpoint_file)
        resume = True
        
        # Show quick summary
        completed_count = sum(1 for f in checkpoint.data['files'].values() 
                            if f.get('status') == 'analysis_complete')
        failed_count = sum(1 for f in checkpoint.data['files'].values() 
                          if f.get('status') == 'failed')
        total = checkpoint.data['metadata'].get('total_files', 0)
        
        logging.info(f"Previous run: {completed_count}/{total} completed, {failed_count} failed")
        logging.info("Automatically resuming from checkpoint (use --fresh to start over)")
    else:
        logging.info(f"No existing checkpoint found, starting fresh")
        checkpoint = CheckpointManager(checkpoint_file)
        resume = False
    
    # Update metadata
    checkpoint.data['metadata']['project_name'] = project_name
    checkpoint.data['metadata']['source_dir'] = str(source_dir)
    
    start_time = time.time()
    
    # Step 1: Collect all files
    logging.info(f"Collecting files from {source_dir}")
    all_files = []
    for root, dirs, files in os.walk(source_dir):
        files = [f for f in files if not f.endswith("json")]
        for f in files:
            all_files.append((Path(root) / f, len(all_files)))
    
    logging.info(f"Found {len(all_files)} files to process")
    
    # Update checkpoint metadata
    checkpoint.data['metadata']['total_files'] = len(all_files)
    checkpoint.save()
    
    # Step 2: Analyze files in parallel (one project per file)
    if not checkpoint.data['stages'].get('analysis_complete'):
        logging.info(f"Starting parallel analysis with {num_workers} workers")
        
        # Get pending files
        pending_files = checkpoint.get_pending_files(all_files) if resume else all_files
        logging.info(f"Files to process: {len(pending_files)} (skipping {len(all_files) - len(pending_files)} completed)")
        
        # Prepare file info for parallel processing
        file_infos = [(str(f[0]), f[1], project_name) for f in pending_files]
    
        project_info_list = []
        
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            # Submit all jobs
            future_to_file = {
                executor.submit(analyze_single_file, file_info, checkpoint): file_info[0] 
                for file_info in file_infos
            }
            
            # Collect results
            completed = 0
            for future in as_completed(future_to_file):
                completed += 1
                if completed % 100 == 0:
                    logging.info(f"Progress: {completed}/{len(pending_files)} files analyzed")
                    
                try:
                    result = future.result()
                    if result:
                        project_info_list.append(result)
                except Exception as e:
                    file_path = future_to_file[future]
                    logging.error(f"Failed to process {file_path}: {e}")
        
        # Add already completed projects if resuming
        if resume:
            completed_projects = checkpoint.get_completed_projects()
            project_info_list.extend(completed_projects)
        
        logging.info(f"Successfully analyzed {len(project_info_list)} files")
        checkpoint.update_stage('analysis_complete', True)
    else:
        logging.info("Analysis stage already complete, loading project info")
        project_info_list = checkpoint.get_completed_projects()
    
    # Step 3: Create FID databases from all projects
    logging.info("Creating FID databases...")
    fid_files = create_fid_from_projects(project_info_list, project_name, checkpoint)
    
    # Step 4: Create SQLite databases from all projects
    logging.info("Creating SQLite databases...")
    db_files = run_matchdb_on_projects(project_info_list, project_name, checkpoint)
    
    # Step 5: Merge all SQLite databases
    if db_files and not checkpoint.data['stages'].get('merge_complete'):
        output_db = Path(f"./db/binfunc_{project_name}.db")
        output_db.parent.mkdir(exist_ok=True)
        
        if output_db.exists():
            os.remove(output_db)
            
        total_functions = merge_databases(db_files, output_db)
        checkpoint.update_stage('merge_complete', True)
        
        # Clean up individual databases (but keep Ghidra projects)
        cleanup_individual_databases(db_files)
        
        logging.info(f"\nComplete! Final database: {output_db}")
        logging.info(f"Total functions: {total_functions}")
        logging.info(f"Created {len(fid_files)} FID files")
        logging.info(f"Ghidra projects preserved in ./ghidra_projects/")
    else:
        logging.error("No databases were created successfully")
    
    elapsed = time.time() - start_time
    logging.info(f"Total processing time: {elapsed:.2f} seconds")
    logging.info(f"Average time per file: {elapsed/len(all_files):.2f} seconds")
    
    # Cleanup temp analysis directory
    temp_analysis_dir = Path(f"./temp_analysis/{project_name}")
    if temp_analysis_dir.exists():
        try:
            shutil.rmtree(temp_analysis_dir)
            logging.info(f"Cleaned up temp analysis directory: {temp_analysis_dir}")
        except Exception as e:
            logging.warning(f"Could not remove temp directory {temp_analysis_dir}: {e}")
    
    logging.info("\nKnowledge database built successfully!")
    logging.info(f"Database location: ./db/binfunc_{project_name}.db")
    logging.info("FID files: ./fidb/")
    logging.info("\nTo identify a firmware, run:")
    logging.info(f"  python3 step2_firmware_identification.py -f <firmware_file>")

if __name__ == "__main__":
    main()