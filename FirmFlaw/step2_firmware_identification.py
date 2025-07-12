#!/usr/bin/env python3
"""
Step 2: Firmware Identification
Identifies functions in target firmware using FID and similarity matching.
Supports both single file (-f) and directory path (-p) analysis.

Multiprocessing approach:
- Stage 1: Parallel project creation (uses all CPU cores)
- Stage 2: Concurrent FID and SimMatch (2 processes total)
  - Process 1: Runs all FID searches sequentially
  - Process 2: Runs all SimMatch operations sequentially
- Stage 3: Parallel mitigation detection (uses all CPU cores)
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
import random
import multiprocessing as mp
from functools import partial

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("Warning: tqdm not installed. Install it for progress bars: pip install tqdm")

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
    if not fidb_dir.exists() or not list(fidb_dir.glob('nrf_*.fidb')):
        return knowledge_dbs[0], None
    
    return knowledge_dbs[0], fidb_dir

def analyze_single_file_worker(args):
    """Worker function for analyzing a single firmware file"""
    file_path, base_project_name, file_index, total_files = args
    file_path = Path(file_path)
    # Create unique project name for this file
    project_name = f"{base_project_name}_{file_path.stem}_{file_index}"
    
    # Create temporary directory for this file
    target_dir = Path(f"./temp_target_{project_name}_{int(time.time())}")
    target_dir.mkdir(exist_ok=True)
    
    try:
        # Copy single file
        shutil.copy2(file_path, target_dir)
        
        # Build Ghidra project for target
        cmd = [
            sys.executable,
            "buildProject.py",
            "./ghidra_projects",
            project_name,
            str(target_dir),
            "-s", "./utils/valid.py"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return (file_path, project_name, False, f"Failed to analyze: {result.stderr}")
        
        # Create database for target
        cmd = [
            sys.executable,
            "MatchDB.py",
            "./ghidra_projects",
            project_name
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return (file_path, project_name, False, f"Failed to create database: {result.stderr}")
        
        return (file_path, project_name, True, "Success")
        
    finally:
        # Cleanup target temp directory
        shutil.rmtree(target_dir, ignore_errors=True)

def analyze_target(target_path, target_project_name, is_directory=False):
    """Analyze target firmware file or directory"""
    if not is_directory:
        # Single file analysis - original behavior
        stage1_start = time.time()
        target_dir = Path(f"./temp_target_{int(time.time())}")
        target_dir.mkdir(exist_ok=True)
        
        try:
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
            
            stage1_time = time.time() - stage1_start
            analyze_target.stage1_time = stage1_time  # Store for summary
            logging.info(f"Stage 1 completed in {stage1_time:.1f}s")
            
            return True
            
        finally:
            # Cleanup target temp directory
            shutil.rmtree(target_dir, ignore_errors=True)
    else:
        # Directory analysis with multiprocessing
        # Collect all firmware files
        firmware_files = []
        for file_path in Path(target_path).rglob('*'):
            if file_path.is_file() and not file_path.name.endswith('.json'):
                firmware_files.append(file_path)
        
        if not firmware_files:
            logging.error(f"No firmware files found in {target_path}")
            return False
        
        logging.info(f"Found {len(firmware_files)} firmware files to analyze")
        
        # Use multiprocessing to analyze files in parallel
        num_processes = min(mp.cpu_count(), len(firmware_files))
        logging.info(f"Using {num_processes} CPU cores for parallel analysis")
        
        # Prepare arguments for multiprocessing
        process_args = []
        for idx, file_path in enumerate(firmware_files, 1):
            process_args.append((file_path, target_project_name, idx, len(firmware_files)))
        
        # Process files in parallel with progress bar
        successful_projects = []
        stage1_start = time.time()
        
        with mp.Pool(processes=num_processes) as pool:
            if TQDM_AVAILABLE:
                # Use tqdm for progress bar
                results = list(tqdm(
                    pool.imap_unordered(analyze_single_file_worker, process_args),
                    total=len(process_args),
                    desc="[Stage 1] Analyzing firmware files",
                    unit="file"
                ))
            else:
                # No progress bar, but still use multiprocessing
                results = pool.map(analyze_single_file_worker, process_args)
        
        stage1_time = time.time() - stage1_start
        logging.info(f"Stage 1 completed in {stage1_time:.1f}s")
        analyze_target.stage1_time = stage1_time  # Store for summary
                
        # Process results
        for file_path, project_name, success, message in results:
            if success:
                successful_projects.append((file_path, project_name))
            else:
                logging.warning(f"Failed to analyze {file_path}: {message}")
        
        if not successful_projects:
            logging.error("All files failed to analyze")
            return False
        
        logging.info(f"Successfully analyzed {len(successful_projects)}/{len(firmware_files)} files")
        
        # Store the list of successful projects for later processing
        analyze_target.successful_projects = successful_projects
        
        return True

def run_all_fid_sequential(project_names, fidb_dir):
    """Run all FID searches using batch processing for better performance"""
    results = []
    start_time = time.time()
    
    print("\n[FID Process Started]\n", flush=True)
    
    # Check if batch processing is available and beneficial
    if len(project_names) > 1 and Path("FidSearchBatch.py").exists():
        # Use batch processing - load FID databases once for all projects
        batch_name = "target_batch" if project_names[0].startswith("target_") else "batch"
        
        # Join all project names with comma
        project_names_str = ",".join(project_names)
        
        fid_cmd = [
            sys.executable,
            "FidSearchBatch.py",
            "./ghidra_projects",
            project_names_str,
            str(fidb_dir),
            "--batch-name", batch_name
        ]
        
        print(f"[FID Batch] Processing {len(project_names)} projects in batch mode", flush=True)
        print(f"[FID Batch] This loads all FID databases once and searches all projects", flush=True)
        
        result = subprocess.run(fid_cmd, capture_output=True, text=True)
        success = result.returncode == 0
        
        if success:
            # All projects succeeded in batch mode
            for project_name in project_names:
                results.append((project_name, True, ""))
            print(f"[FID Batch] Completed all {len(project_names)} projects in {time.time() - start_time:.1f}s", flush=True)
        else:
            # Batch failed, fall back to individual processing
            print(f"[FID Batch] Batch processing failed, falling back to individual mode", flush=True)
            print(f"[FID Batch] Error: {result.stderr[:200]}", flush=True)
            
            # Fall back to individual processing
            for idx, project_name in enumerate(project_names, 1):
                fid_cmd = [
                    sys.executable,
                    "FidSearchAll.py",
                    "./ghidra_projects",
                    project_name,
                    str(fidb_dir)
                ]
                
                project_start = time.time()
                print(f"[FID {idx}/{len(project_names)}] Processing: {project_name}", flush=True)
                result = subprocess.run(fid_cmd, capture_output=True, text=True)
                success = result.returncode == 0
                project_time = time.time() - project_start
                
                results.append((project_name, success, result.stderr if not success else ""))
                
                if success:
                    print(f"[FID {idx}/{len(project_names)}] Completed in {project_time:.1f}s: {project_name}", flush=True)
                else:
                    print(f"[FID {idx}/{len(project_names)}] Failed after {project_time:.1f}s: {project_name}", flush=True)
                
                # Show progress estimate
                elapsed = time.time() - start_time
                avg_time = elapsed / idx
                remaining = (len(project_names) - idx) * avg_time
                print(f"[FID] Progress: {idx}/{len(project_names)} - Elapsed: {elapsed:.1f}s - ETA: {remaining:.1f}s", flush=True)
    else:
        # Single project or batch script not available - use original approach
        for idx, project_name in enumerate(project_names, 1):
            fid_cmd = [
                sys.executable,
                "FidSearchAll.py",
                "./ghidra_projects",
                project_name,
                str(fidb_dir)
            ]
            
            project_start = time.time()
            print(f"[FID {idx}/{len(project_names)}] Processing: {project_name}", flush=True)
            result = subprocess.run(fid_cmd, capture_output=True, text=True)
            success = result.returncode == 0
            project_time = time.time() - project_start
            
            results.append((project_name, success, result.stderr if not success else ""))
            
            if success:
                print(f"[FID {idx}/{len(project_names)}] Completed in {project_time:.1f}s: {project_name}", flush=True)
            else:
                print(f"[FID {idx}/{len(project_names)}] Failed after {project_time:.1f}s: {project_name}", flush=True)
            
            # Show progress estimate
            elapsed = time.time() - start_time
            avg_time = elapsed / idx
            remaining = (len(project_names) - idx) * avg_time
            print(f"[FID] Progress: {idx}/{len(project_names)} - Elapsed: {elapsed:.1f}s - ETA: {remaining:.1f}s", flush=True)
    
    total_time = time.time() - start_time
    print(f"\n[FID Process Completed] All searches finished in {total_time:.1f}s\n", flush=True)
    return results

def run_all_sim_sequential(project_names, knowledge_db, sample_db_dir):
    """Run all SimMatch operations sequentially in a single process"""
    results = []
    start_time = time.time()
    
    print("\n[SimMatch Process Started]\n", flush=True)
    
    for idx, project_name in enumerate(project_names, 1):
        target_db_path = Path(sample_db_dir) / f"binfunc_{project_name}.db"
        
        sim_cmd = [
            sys.executable,
            "SimMatch.py",
            str(target_db_path),
            str(knowledge_db)
        ]
        
        project_start = time.time()
        print(f"[SimMatch {idx}/{len(project_names)}] Processing: {project_name}", flush=True)
        result = subprocess.run(sim_cmd, capture_output=True, text=True)
        success = result.returncode == 0
        project_time = time.time() - project_start
        
        results.append((project_name, success, result.stderr if not success else ""))
        
        if success:
            print(f"[SimMatch {idx}/{len(project_names)}] Completed in {project_time:.1f}s: {project_name}", flush=True)
        else:
            print(f"[SimMatch {idx}/{len(project_names)}] Failed after {project_time:.1f}s: {project_name}", flush=True)
        
        # Show progress estimate
        elapsed = time.time() - start_time
        avg_time = elapsed / idx
        remaining = (len(project_names) - idx) * avg_time
        print(f"[SimMatch] Progress: {idx}/{len(project_names)} - Elapsed: {elapsed:.1f}s - ETA: {remaining:.1f}s", flush=True)
    
    total_time = time.time() - start_time
    print(f"\n[SimMatch Process Completed] All matches finished in {total_time:.1f}s\n", flush=True)
    return results

def run_identification(target_project_name, knowledge_db, fidb_dir):
    """Run FID search and similarity matching using 2 concurrent processes"""
    logging.info("Running FID search and similarity matching...")
    
    # Get sample db dir
    sample_db_dir = get_current_db_dir()
    
    # Check if we have multiple projects from directory analysis
    if hasattr(analyze_target, 'successful_projects'):
        # Multiple projects from directory analysis
        projects = analyze_target.successful_projects
        project_names = [proj_name for _, proj_name in projects]
        logging.info(f"Processing {len(project_names)} projects using 2 concurrent processes...")
        logging.info("Process 1: FID Search (all projects sequentially)")
        logging.info("Process 2: SimMatch (all projects sequentially)")
        
        # Create a pool with exactly 2 processes
        identification_start = time.time()
        with mp.Pool(processes=2) as pool:
            # Start both tasks asynchronously
            logging.info("Starting concurrent FID and SimMatch processes...")
            fid_task = pool.apply_async(run_all_fid_sequential, (project_names, fidb_dir))
            sim_task = pool.apply_async(run_all_sim_sequential, (project_names, knowledge_db, sample_db_dir))
            
            # Wait for both to complete
            print("\n[Stage 2] Running FID and SimMatch concurrently (2 processes)...", flush=True)
            print("Note: FID and SimMatch outputs will be interleaved below:\n", flush=True)
            
            # Get results
            fid_results = fid_task.get()
            sim_results = sim_task.get()
        
        identification_time = time.time() - identification_start
        logging.info(f"Stage 2 completed in {identification_time:.1f}s")
        run_identification.stage2_time = identification_time  # Store for summary
        
        # Process FID results
        fid_successful = []
        for proj_name, success, error in fid_results:
            if success:
                fid_successful.append(proj_name)
            else:
                logging.warning(f"FID search failed for {proj_name}: {error[:200]}")
        
        logging.info(f"FID search completed for {len(fid_successful)}/{len(project_names)} projects")
        
        # Process SimMatch results
        sim_successful = []
        for proj_name, success, error in sim_results:
            if success:
                sim_successful.append(proj_name)
            else:
                logging.warning(f"SimMatch failed for {proj_name}: {error[:200]}")
        
        logging.info(f"SimMatch completed for {len(sim_successful)}/{len(project_names)} projects")
        
        # Overall success if at least one project succeeded in either
        return len(fid_successful) > 0 or len(sim_successful) > 0
        
    else:
        # Single project - run sequentially
        logging.info("Processing single project...")
        
        identification_start = time.time()
        
        # Run FID
        fid_results = run_all_fid_sequential([target_project_name], fidb_dir)
        proj_name, fid_success, fid_error = fid_results[0]
        if fid_success:
            logging.info("FID search completed successfully")
        else:
            logging.error(f"FID search failed: {fid_error}")
        
        # Run SimMatch
        sim_results = run_all_sim_sequential([target_project_name], knowledge_db, sample_db_dir)
        proj_name, sim_success, sim_error = sim_results[0]
        if sim_success:
            logging.info("SimMatch completed successfully")
        else:
            logging.error(f"SimMatch failed: {sim_error}")
        
        identification_time = time.time() - identification_start
        run_identification.stage2_time = identification_time  # Store for summary
        
        return fid_success and sim_success

def run_mitigation_worker(project_name):
    """Worker function for running mitigation detection"""
    cmd = [
        sys.executable,
        "Mitigation.py",
        "./ghidra_projects",
        project_name
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return (project_name, result.returncode == 0, result.stderr if result.returncode != 0 else "")

def run_mitigation_detection(target_project_name):
    """Run mitigation method detection using multiprocessing"""
    logging.info("Running mitigation method detection...")
    
    # Check if we have multiple projects from directory analysis
    if hasattr(analyze_target, 'successful_projects'):
        # Multiple projects from directory analysis
        projects = analyze_target.successful_projects
        project_names = [proj_name for _, proj_name in projects]
        logging.info(f"Running mitigation detection for {len(project_names)} projects...")
        
        # Determine number of processes
        num_processes = min(mp.cpu_count(), len(project_names))
        logging.info(f"Using {num_processes} CPU cores for parallel mitigation detection")
        
        # Run mitigation detection in parallel
        stage3_start = time.time()
        with mp.Pool(processes=num_processes) as pool:
            if TQDM_AVAILABLE:
                results = list(tqdm(
                    pool.imap_unordered(run_mitigation_worker, project_names),
                    total=len(project_names),
                    desc="[Stage 3] Mitigation Detection",
                    unit="project"
                ))
            else:
                results = pool.map(run_mitigation_worker, project_names)
        
        stage3_time = time.time() - stage3_start
        logging.info(f"Stage 3 completed in {stage3_time:.1f}s")
        run_mitigation_detection.stage3_time = stage3_time  # Store for summary
        
        # Check results
        successful = 0
        for proj_name, success, error in results:
            if success:
                successful += 1
            else:
                logging.warning(f"Mitigation detection failed for {proj_name}: {error[:200]}")
        
        logging.info(f"Mitigation detection completed for {successful}/{len(project_names)} projects")
        return successful > 0
        
    else:
        # Single project
        stage3_start = time.time()
        proj_name, success, error = run_mitigation_worker(target_project_name)
        
        if success:
            logging.info("Mitigation detection completed successfully")
        else:
            logging.error(f"Mitigation detection failed: {error}")
        
        stage3_time = time.time() - stage3_start
        run_mitigation_detection.stage3_time = stage3_time  # Store for summary
        
        return success

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
    # Get start time for overall timing
    overall_start_time = time.time()
    
    parser = argparse.ArgumentParser(
        description='Step 2: Identify functions in target firmware',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f firmware.bin                   # Analyze single firmware file
  %(prog)s -p ./firmware_directory           # Analyze all files in directory
                                             # Stage 1: Parallel project creation (all CPUs)
                                             # Stage 2: Concurrent FID + SimMatch (2 processes)
                                             # Stage 3: Parallel mitigation detection (all CPUs)
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
    logging.info(f"CPU cores available: {mp.cpu_count()}")
    if is_directory:
        logging.info("Multiprocessing strategy:")
        logging.info("  - Stage 1: Parallel project creation (all CPU cores)")
        logging.info("  - Stage 2: Concurrent FID + SimMatch (2 processes)")
        logging.info("  - Stage 3: Parallel mitigation detection (all CPU cores)")
    
    if is_directory and not TQDM_AVAILABLE:
        logging.info("Tip: Install tqdm for progress bars: pip install tqdm")
    
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
    print("\n" + "="*80, flush=True)
    print("[Stage 1] Ghidra Project Creation and Database Generation", flush=True)
    print("="*80 + "\n", flush=True)
    
    if not analyze_target(target_path, target_project_name, is_directory):
        logging.error("Failed to analyze target")
        sys.exit(1)
    
    # Step 2: Run identification (FID search and similarity matching)
    # Ensure context is saved
    save_current_context()
    
    print("\n" + "="*80, flush=True)
    print("[Stage 2] FID Search and Similarity Matching", flush=True)
    print("="*80 + "\n", flush=True)
    
    if not run_identification(target_project_name, knowledge_db, fidb_dir):
        logging.error("Identification process failed")
        # Continue anyway to get partial results
    
    # Step 3: Run mitigation detection (unless skipped)
    if not args.skip_mitigation:
        print("\n" + "="*80, flush=True)
        print("[Stage 3] Mitigation Detection", flush=True)
        print("="*80 + "\n", flush=True)
        
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
    
    if hasattr(analyze_target, 'successful_projects'):
        # Multiple projects were analyzed
        logging.info(f"- Analyzed {len(analyze_target.successful_projects)} firmware files")
        for file_path, proj_name in analyze_target.successful_projects:
            logging.info(f"  - {file_path.name} -> {proj_name}")
        logging.info(f"- FID results: FidSearchAll_*_*.json")
        logging.info(f"- SimMatch results: SimMatch_*.json")
    else:
        logging.info(f"- FID results: FidSearchAll_{target_project_name}_*.json")
        logging.info(f"- SimMatch results: SimMatch_*.json")
    
    logging.info("- Summary: target_analysis_results.md")
    
    # Calculate total time
    total_time = time.time() - overall_start_time
    logging.info(f"\nTotal analysis time: {total_time:.1f}s ({total_time/60:.1f} minutes)")
    
    # Show time breakdown
    print("\n" + "="*80)
    print("Time Summary:")
    print("="*80)
    if hasattr(analyze_target, 'stage1_time'):
        print(f"Stage 1 (Project Creation): {analyze_target.stage1_time:.1f}s")
    if hasattr(run_identification, 'stage2_time'):
        print(f"Stage 2 (FID + SimMatch):   {run_identification.stage2_time:.1f}s")
    if hasattr(run_mitigation_detection, 'stage3_time'):
        print(f"Stage 3 (Mitigation):       {run_mitigation_detection.stage3_time:.1f}s")
    
    other_time = total_time - getattr(analyze_target, 'stage1_time', 0) - getattr(run_identification, 'stage2_time', 0) - getattr(run_mitigation_detection, 'stage3_time', 0)
    print(f"Other operations:           {other_time:.1f}s")
    print("-"*80)
    print(f"Total time:                 {total_time:.1f}s ({total_time/60:.1f} minutes)")
    print("="*80)
    
    print(f"\nIdentification complete! Results saved to: {sample_folder}")

if __name__ == "__main__":
    main()