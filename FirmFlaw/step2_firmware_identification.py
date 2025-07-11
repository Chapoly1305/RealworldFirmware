#!/usr/bin/env python3
"""
Step 2: Firmware Identification
Identifies functions in target firmware using FID and similarity matching.
Supports both single file (-f) and directory path (-p) analysis.
"""
import os
import sys
import time
import shutil
import subprocess
import argparse
import logging
from pathlib import Path
from datetime import datetime
import multiprocessing as mp

from utils.sample_folders import (
    set_current_analysis, get_current_sample_folder, 
    get_current_temp_dir, get_current_db_dir, get_current_logs_dir,
    cleanup_legacy_folders, save_current_context
)

log_time = time.strftime("%m_%d_%H_%M")

def setup_logging(target_name, sample_logs_dir=None):
    """Setup logging configuration"""
    # Use sample-specific logs directory if provided, otherwise use global
    if sample_logs_dir:
        log_dir = sample_logs_dir
    else:
        log_dir = Path('./logs')
        log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / f'step2_firmware_identification_{target_name}_{log_time}.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def check_prerequisites():
    """Check if knowledge database exists"""
    # Look for any database in ./db/
    db_dir = Path('./db')
    if not db_dir.exists():
        return None, None
    
    # Find the knowledge database (usually binfunc_firmware_match.db)
    knowledge_dbs = list(db_dir.glob('binfunc_*.db'))
    if not knowledge_dbs:
        return None, None
    
    # Check if FID directory exists
    fidb_dir = Path('./fidb')
    if not fidb_dir.exists() or not list(fidb_dir.glob('**/*.fidb')):
        return knowledge_dbs[0], None
    
    return knowledge_dbs[0], fidb_dir

def analyze_target(target_path, target_project_name, is_directory=False):
    """Analyze target firmware file or directory"""
    # Create temporary directory for target processing
    target_dir = Path(f"./temp_target_{int(time.time())}")
    target_dir.mkdir(exist_ok=True)
    
    try:
        if is_directory:
            # Copy all files from directory
            for file_path in Path(target_path).rglob('*'):
                if file_path.is_file() and not file_path.name.endswith('.json'):
                    relative_path = file_path.relative_to(target_path)
                    dest_path = target_dir / relative_path
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(file_path, dest_path)
        else:
            # Copy single file
            shutil.copy2(target_path, target_dir)
        
        # Build Ghidra project for target
        cmd = [
            sys.executable,
            "buildProject.py",
            "./ghidra_projects",
            target_project_name,
            str(target_dir),
            "-s", "./utils/valid.py"
        ]
        
        logging.info(f"Analyzing target: {target_path}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logging.error(f"Failed to analyze target: {result.stderr}")
            return False
        
        # Create database for target
        cmd = [
            sys.executable,
            "MatchDB.py",
            "./ghidra_projects",
            target_project_name
        ]
        
        logging.info("Creating database for target")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logging.error(f"Failed to create target database: {result.stderr}")
            return False
        
        return True
        
    finally:
        # Cleanup target temp directory
        shutil.rmtree(target_dir, ignore_errors=True)

def run_identification(target_project_name, knowledge_db, fidb_dir):
    """Run FID search and similarity matching concurrently"""
    logging.info("Running FID search and similarity matching concurrently...")
    
    # Prepare commands
    fid_cmd = [
        sys.executable,
        "FidSearchAll.py",
        "./ghidra_projects",
        target_project_name,
        str(fidb_dir)
    ]
    
    # Get the database path from sample-specific directory
    sample_db_dir = get_current_db_dir()
    target_db_path = sample_db_dir / f"binfunc_{target_project_name}.db"
    
    sim_cmd = [
        sys.executable,
        "SimMatch.py",
        str(target_db_path),
        str(knowledge_db)
    ]
    
    # Start both processes concurrently
    logging.info("Starting FID search process...")
    fid_process = subprocess.Popen(fid_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    logging.info("Starting similarity matching process...")
    sim_process = subprocess.Popen(sim_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Wait for both processes to complete
    logging.info("Waiting for concurrent processes to complete...")
    fid_stdout, fid_stderr = fid_process.communicate()
    sim_stdout, sim_stderr = sim_process.communicate()
    
    # Check results
    fid_success = fid_process.returncode == 0
    sim_success = sim_process.returncode == 0
    
    if not fid_success:
        logging.error(f"FID search failed: {fid_stderr}")
    else:
        logging.info("FID search completed successfully")
        
    if not sim_success:
        logging.error(f"SimMatch failed: {sim_stderr}")
    else:
        logging.info("SimMatch completed successfully")
    
    return fid_success and sim_success

def run_mitigation_detection(target_project_name):
    """Run mitigation method detection"""
    logging.info("Running mitigation method detection...")
    
    cmd = [
        sys.executable,
        "Mitigation.py",
        "./ghidra_projects",
        target_project_name
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        logging.error(f"Mitigation detection failed: {result.stderr}")
        return False
    
    logging.info("Mitigation detection completed successfully")
    return True

def merge_csv_results():
    """Merge CSV fragments"""
    logging.info("Merging CSV results...")
    
    cmd = [
        sys.executable,
        "merge_csv_results.py",
        "-y"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        logging.error(f"CSV merge failed: {result.stderr}")
        return False
    
    logging.info("CSV merge completed successfully")
    return True

def generate_final_results():
    """Generate final results"""
    logging.info("Generating final results...")
    
    cmd = [
        sys.executable,
        "ResGenTarget.py",
        "2"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        logging.error(f"Result generation failed: {result.stderr}")
        return False
    
    logging.info("Result generation completed successfully")
    return True

def main():
    parser = argparse.ArgumentParser(
        description='Step 2: Identify functions in target firmware',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f firmware.bin                   # Analyze single firmware file
  %(prog)s -p ./firmware_directory           # Analyze all files in directory
  %(prog)s -f firmware.bin --skip-mitigation # Skip mitigation detection
  %(prog)s -f firmware.bin --name my_target  # Use custom project name
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='Single firmware file to analyze')
    group.add_argument('-p', '--path', help='Directory containing firmware files to analyze')
    
    parser.add_argument('-n', '--name', help='Custom project name (default: auto-generated from file/path)')
    parser.add_argument('--skip-mitigation', action='store_true', 
                        help='Skip mitigation method detection')
    parser.add_argument('--knowledge-db', help='Path to knowledge database (default: auto-detect)')
    
    args = parser.parse_args()
    
    # Determine target path and name
    if args.file:
        target_path = Path(args.file)
        if not target_path.exists():
            print(f"Error: File {target_path} does not exist")
            sys.exit(1)
        is_directory = False
        default_name = f"target_{target_path.stem}"
    else:
        target_path = Path(args.path)
        if not target_path.exists():
            print(f"Error: Directory {target_path} does not exist")
            sys.exit(1)
        is_directory = True
        default_name = f"target_{target_path.name}"
    
    target_project_name = args.name or default_name
    
    # Set up sample-specific folder structure FIRST
    analysis_timestamp = datetime.now().strftime('%m_%d_%H_%M')
    set_current_analysis(target_project_name, analysis_timestamp)
    save_current_context()  # Save context for other scripts to use
    
    sample_folder = get_current_sample_folder()
    sample_db_dir = get_current_db_dir()
    sample_temp_dir = get_current_temp_dir()
    sample_logs_dir = get_current_logs_dir()
    
    # Setup logging with sample-specific logs directory
    setup_logging(target_project_name, sample_logs_dir)
    
    logging.info(f"Starting firmware identification for: {target_path}")
    logging.info(f"Project name: {target_project_name}")
    
    # Check prerequisites
    if args.knowledge_db:
        knowledge_db = Path(args.knowledge_db)
        if not knowledge_db.exists():
            logging.error(f"Specified knowledge database {knowledge_db} does not exist")
            sys.exit(1)
        fidb_dir = Path('./fidb')
    else:
        knowledge_db, fidb_dir = check_prerequisites()
        if not knowledge_db:
            logging.error("No knowledge database found. Please run step1_build_knowledge_db.py first")
            sys.exit(1)
        if not fidb_dir:
            logging.warning("No FID files found. FID search will be skipped")
    
    logging.info(f"Using knowledge database: {knowledge_db}")
    logging.info(f"Analysis results will be saved to: {sample_folder}")
    
    # Step 1: Analyze target
    if not analyze_target(target_path, target_project_name, is_directory):
        logging.error("Failed to analyze target")
        sys.exit(1)
    
    # Step 2: Run identification (FID search and similarity matching)
    if not run_identification(target_project_name, knowledge_db, fidb_dir):
        logging.error("Identification process failed")
        # Continue anyway to get partial results
    
    # Step 3: Run mitigation detection (unless skipped)
    if not args.skip_mitigation:
        if not run_mitigation_detection(target_project_name):
            logging.warning("Mitigation detection failed, continuing...")
    else:
        logging.info("Skipping mitigation detection as requested")
    
    # Step 4: Merge CSV results
    if not merge_csv_results():
        logging.warning("CSV merge failed, continuing...")
    
    # Step 5: Generate final results
    if not generate_final_results():
        logging.warning("Result generation failed")
    
    # Clean up analysis context file
    context_file = Path(".analysis_context.json")
    if context_file.exists():
        os.remove(context_file)
    
    # Clean up legacy folders if empty
    cleanup_legacy_folders()
    
    logging.info("\nIdentification complete!")
    logging.info(f"Results are organized in: {sample_folder}")
    logging.info(f"- Check {sample_folder}/res/ for analysis results")
    logging.info(f"- FID results: FidSearchAll_{target_project_name}_*.json")
    logging.info(f"- SimMatch results: SimMatch_*.json")
    logging.info("- Summary: target_analysis_results.md")
    
    print(f"\nIdentification complete! Results saved to: {sample_folder}")

if __name__ == "__main__":
    main()