#!/usr/bin/env python3
"""
Optimized batch FID search that loads databases ONCE and processes multiple projects
This dramatically improves performance when analyzing multiple firmware files
"""
import os
import sys
import json
import time
import logging
import argparse
from pathlib import Path
from collections import defaultdict
from utils.launcher import HeadlessLoggingPyhidraLauncher
from utils.sample_folders import get_current_res_dir, get_current_logs_dir, load_current_context

def setup_logging(batch_name):
    """Setup logging configuration"""
    log_time = time.strftime("%m_%d_%H_%M")
    
    # Use sample-specific logs directory for target analysis
    if batch_name.startswith('target_'):
        # Try to load the context first
        if load_current_context():
            try:
                log_dir = get_current_logs_dir()
            except ValueError:
                # Fallback if no current analysis context
                log_dir = Path('./logs')
        else:
            # Fallback if context not loaded
            log_dir = Path('./logs')
    else:
        log_dir = Path('./logs')
    
    log_dir.mkdir(exist_ok=True, parents=True)
    
    # Get log level from environment variable, default to INFO
    log_level_str = os.environ.get('LOGLEVEL', 'INFO').upper()
    log_level = getattr(logging, log_level_str, logging.INFO)
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / f'FidSearchBatch_{batch_name}_{log_time}.log'),
            # Only add console handler if not suppressing output
            logging.StreamHandler(sys.stdout) if log_level < logging.ERROR else logging.NullHandler()
        ]
    )
    return log_time

def processMatches(result, program, nameAnalysis, monitor):
    """Process FID matches"""
    matches_ = []
    if result.matches.size() == 0:
        return matches_
    
    for match in result.matches:
        monitor.checkCancelled()
        fname_ = match.getFunctionRecord().getName()
        library = match.getLibraryRecord().toString()
        matches_.append((fname_, library))
    
    return matches_

def search_fid_comprehensive(program, fidQueryService, service, monitor, nameAnalysis):
    """
    Search against ALL loaded FID databases using pre-loaded query service
    """
    from java.io import IOException
    from ghidra.util.exception import CancelledException, VersionException
    
    SCORE_THRESHOLD = 14.6
    pmatches = {}
    
    if not service.canProcess(program.getLanguage()):
        logging.error(f'{program.getName()} cannot be processed by function ID')
        return pmatches
    
    try:
        # Use the pre-loaded fidQueryService instead of creating a new one
        result_ = service.processProgram(program, fidQueryService, SCORE_THRESHOLD, monitor)
        
        if result_ is None:
            logging.info(f"Search failed for {program.getName()}")
            return pmatches
        
        for entry in result_:
            monitor.checkCancelled()
            monitor.incrementProgress(1)
            if entry.function.isThunk():
                continue
            if entry.matches.isEmpty():
                logging.debug(f'No result for {entry.function.getName()}')
            else:
                fmatches = processMatches(entry, program, nameAnalysis, monitor)
                if len(fmatches) != 0:
                    pmatches[entry.function.getName()] = fmatches
                    
    except CancelledException as e:
        logging.info('Search cancelled')
    except VersionException as e:
        logging.error(f"Version Exception {e.getMessage()}")
    except IOException as e:
        logging.error(f"IOException {e.getMessage()}")
    
    return pmatches

def main():
    parser = argparse.ArgumentParser(description="Batch FID search - loads databases once, searches all projects")
    parser.add_argument("project_path", type=Path, help="Path to Ghidra projects")
    parser.add_argument("project_names", help="Comma-separated list of project names to search")
    parser.add_argument("fidb_path", type=Path, help="Root directory containing FID files")
    parser.add_argument("--batch-name", default="batch", help="Name for this batch operation")
    args = parser.parse_args()
    
    # Parse project names
    project_names = [name.strip() for name in args.project_names.split(',')]
    
    log_time = setup_logging(args.batch_name)
    
    logging.info(f"Starting batch FID search for {len(project_names)} projects")
    logging.info(f"Projects: {', '.join(project_names)}")
    logging.info(f"FID directory: {args.fidb_path}")
    
    # Determine pyhidra log path
    if args.batch_name.startswith('target_'):
        # Try to load the context first
        if load_current_context():
            try:
                logs_dir = get_current_logs_dir()
                pyhidra_log_path = logs_dir / f'Pyhidra_{args.batch_name}_batch.log'
            except ValueError:
                # Fallback if no current analysis context
                pyhidra_log_path = f'./logs/Pyhidra_{args.batch_name}_batch.log'
        else:
            # Fallback if context not loaded
            pyhidra_log_path = f'./logs/Pyhidra_{args.batch_name}_batch.log'
    else:
        pyhidra_log_path = f'./logs/Pyhidra_{args.batch_name}_batch.log'
    
    launcher = HeadlessLoggingPyhidraLauncher(
        verbose=True, 
        log_path=str(pyhidra_log_path)
    )
    launcher.start()
    
    try:
        # Import Ghidra classes
        from ghidra.base.project import GhidraProject
        from ghidra.feature.fid.db import FidFileManager
        from ghidra.feature.fid.service import FidService, MatchNameAnalysis
        from ghidra.util.task import ConsoleTaskMonitor
        from java.io import File, IOException
        
        monitor = ConsoleTaskMonitor()
        nameAnalysis = MatchNameAnalysis()
        
        # Find ALL .fidb files
        fidb_files = []
        logging.info(f"Scanning for .fidb files in: {args.fidb_path}")
        
        for fidb_file in args.fidb_path.rglob("*.fidb"):
            # Extract relative path for organization
            rel_path = fidb_file.relative_to(args.fidb_path)
            parent_dir = rel_path.parent.name if rel_path.parent != Path('.') else 'root'
            fidb_files.append({
                'path': fidb_file,
                'name': fidb_file.stem,
                'parent': parent_dir,
                'rel_path': str(rel_path)
            })
        
        logging.info(f"Found {len(fidb_files)} FID files")
        
        # Group by parent directory for statistics
        by_parent = defaultdict(list)
        for fid in fidb_files:
            by_parent[fid['parent']].append(fid)
        
        # Load ALL .fidb files ONCE
        logging.info("Loading all FID databases into memory (this happens only once)...")
        load_start_time = time.time()
        loaded_count = 0
        failed_count = 0
        
        for fid_info in fidb_files:
            try:
                FidFileManager.getInstance().addUserFidFile(File(str(fid_info['path'])))
                loaded_count += 1
                
                if loaded_count % 100 == 0:
                    logging.info(f"Loaded {loaded_count}/{len(fidb_files)} databases...")
                    
            except Exception as e:
                failed_count += 1
                logging.debug(f"Could not load {fid_info['name']}: {e}")
        
        load_time = time.time() - load_start_time
        logging.info(f"Successfully loaded {loaded_count} FID databases in {load_time:.1f}s ({failed_count} failed)")
        
        # Verify loaded databases
        loaded_fid_files = FidFileManager.getInstance().getUserAddedFiles()
        logging.info(f"FidFileManager reports {len(loaded_fid_files)} active databases")
        
        # Initialize FID service and query service ONCE
        service = FidService()
        
        # We'll need to get a language from the first project to initialize the query service
        first_project_name = project_names[0]
        try:
            first_project = GhidraProject.openProject(args.project_path, first_project_name, True)
            first_files = first_project.getRootFolder().getFiles()
            if first_files:
                first_program = first_project.openProgram('/', first_files[0].getName(), True)
                language = first_program.getLanguage()
                
                # Create query service ONCE for all searches
                logging.info("Creating FID query service (this happens only once)...")
                fidQueryService = service.openFidQueryService(language, False)
                
                first_project.close(first_program)
            else:
                logging.error(f"No files found in first project {first_project_name}")
                first_project.close()
                return
            first_project.close()
        except IOException:
            logging.error(f'Could not open first project {first_project_name} to get language')
            return
        
        # Now process ALL projects using the pre-loaded databases
        all_results = {}
        project_results = {}
        search_start_time = time.time()
        
        for proj_idx, project_name in enumerate(project_names, 1):
            logging.info(f"\n[{proj_idx}/{len(project_names)}] Processing project: {project_name}")
            project_start_time = time.time()
            
            try:
                project = GhidraProject.openProject(args.project_path, project_name, True)
                logging.info(f'Opened project: {project.project.name}')
            except IOException:
                logging.error(f'Could not open project {args.project_path}/{project_name}')
                continue
            
            # Results for this project
            all_matches = {}
            match_num = []
            
            project_files = project.getRootFolder().getFiles()
            logging.info(f"Searching {len(project_files)} programs in {project_name}")
            
            for file_ in project_files:
                name_ = file_.getName()
                logging.debug(f"Searching {name_}...")
                
                program_ = project.openProgram('/', file_.getName(), True)
                
                # Search using the pre-loaded databases and query service
                pmatches = search_fid_comprehensive(program_, fidQueryService, service, monitor, nameAnalysis)
                
                if len(pmatches) != 0:
                    match_num.append([name_, len(pmatches)])
                    
                    # Clean up name
                    noheader_pos = name_.find('noheader')
                    if noheader_pos != -1:
                        clean_name = name_[:noheader_pos]
                    else:
                        clean_name = name_
                        
                    all_matches[clean_name] = pmatches
                
                project.close(program_)
            
            project_time = time.time() - project_start_time
            logging.info(f"Project {project_name} completed in {project_time:.1f}s")
            
            # Store results for this project
            project_results[project_name] = {
                'matches': all_matches,
                'match_counts': match_num,
                'search_time': project_time
            }
            
            # Generate per-project output files
            summary_by_version = {}
            detailed_results = {}
            
            # Organize matches by version
            for clean_name, pmatches in all_matches.items():
                for parent in by_parent.keys():
                    if parent not in summary_by_version:
                        summary_by_version[parent] = {
                            'total_matches': 0,
                            'fid_count': len(by_parent[parent]),
                            'details': {}
                        }
                        detailed_results[parent] = {}
                    
                    if 'all_databases' not in summary_by_version[parent]['details']:
                        summary_by_version[parent]['details']['all_databases'] = {
                            'count': len(pmatches),
                            'matches': pmatches
                        }
                        detailed_results[parent]['all_databases'] = {
                            'count': len(pmatches),
                            'matches': pmatches
                        }
                        summary_by_version[parent]['total_matches'] += len(pmatches)
            
            # Determine output directory
            if project_name.startswith('target_'):
                try:
                    res_dir = get_current_res_dir()
                except ValueError:
                    import os
                    os.makedirs('./res', exist_ok=True)
                    res_dir = Path('./res')
            else:
                import os
                os.makedirs('./res', exist_ok=True)
                res_dir = Path('./res')
            
            # Save per-project results
            output_file = res_dir / f"FidSearchAll_{project_name}_{log_time}.json"
            with open(output_file, 'w') as f:
                json.dump({
                    'project': project_name,
                    'timestamp': log_time,
                    'summary': summary_by_version,
                    'detailed_results': detailed_results,
                    'batch_search': True,
                    'databases_loaded': loaded_count,
                    'search_time': project_time
                }, f, indent=2)
            
            logging.info(f"Results for {project_name} saved to: {output_file}")
            
            project.close()
        
        total_search_time = time.time() - search_start_time
        
        # Summary statistics
        logging.info("\n=== BATCH FID SEARCH SUMMARY ===")
        logging.info(f"Total projects processed: {len(project_names)}")
        logging.info(f"FID databases loaded: {loaded_count}")
        logging.info(f"Database load time: {load_time:.1f}s (one-time cost)")
        logging.info(f"Total search time: {total_search_time:.1f}s")
        logging.info(f"Average time per project: {total_search_time/len(project_names):.1f}s")
        logging.info(f"Time saved by batch processing: {(load_time * (len(project_names)-1)):.1f}s")
        
        # Save batch summary
        batch_summary_file = res_dir / f"FidSearchBatch_Summary_{log_time}.json"
        with open(batch_summary_file, 'w') as f:
            json.dump({
                'batch_name': args.batch_name,
                'projects': project_names,
                'databases_loaded': loaded_count,
                'load_time': load_time,
                'total_search_time': total_search_time,
                'average_time_per_project': total_search_time/len(project_names),
                'time_saved': load_time * (len(project_names)-1),
                'project_summaries': {
                    name: {
                        'total_matches': sum(m[1] for m in data['match_counts']),
                        'programs_with_matches': len(data['matches']),
                        'search_time': data['search_time']
                    }
                    for name, data in project_results.items()
                }
            }, f, indent=2)
        
        logging.info(f"\nBatch summary saved to: {batch_summary_file}")
        
    except Exception as e:
        logging.error(f"Batch FID search failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()