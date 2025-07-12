#!/usr/bin/env python3
"""
Enhanced FID search that loads ALL .fidb files at once for comprehensive matching
REPLACES the existing FidSearchAll.py with much better performance and coverage
"""
import os
import sys
import json
import time
import logging
import argparse
from pathlib import Path
from utils.launcher import HeadlessLoggingPyhidraLauncher
from utils.sample_folders import get_current_res_dir, get_current_logs_dir, load_current_context

def setup_logging(project_name):
    """Setup logging configuration"""
    log_time = time.strftime("%m_%d_%H_%M")
    
    # Use sample-specific logs directory for target analysis
    if project_name.startswith('target_'):
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
            logging.FileHandler(log_dir / f'FidSearchAll_{project_name}_{log_time}.log'),
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

def search_fid_comprehensive(program, monitor, nameAnalysis):
    """
    Search against ALL loaded FID databases simultaneously
    This is much more efficient than searching each database individually
    """
    from java.io import IOException
    from ghidra.util.exception import CancelledException, VersionException
    from ghidra.feature.fid.service import FidService
    
    SCORE_THRESHOLD = 14.6
    service = FidService()
    pmatches = {}
    
    if not service.canProcess(program.getLanguage()):
        logging.error(f'{program.getName()} cannot be processed by function ID')
        return pmatches
    
    try:
        fidQueryService = service.openFidQueryService(program.getLanguage(), False)
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
    parser = argparse.ArgumentParser(description="Enhanced FID search using ALL databases")
    parser.add_argument("project_path", type=Path, help="Path to Ghidra projects")
    parser.add_argument("project_name", help="Name of target project to search")
    parser.add_argument("fidb_path", type=Path, help="Root directory containing FID files")
    args = parser.parse_args()
    
    log_time = setup_logging(args.project_name)
    
    logging.info(f"Starting enhanced FID search for project: {args.project_name}")
    logging.info(f"FID directory: {args.fidb_path}")
    
    # Determine pyhidra log path
    if args.project_name.startswith('target_'):
        # Try to load the context first
        if load_current_context():
            try:
                logs_dir = get_current_logs_dir()
                pyhidra_log_path = logs_dir / f'Pyhidra_{args.project_name}_enhanced.log'
            except ValueError:
                # Fallback if no current analysis context
                pyhidra_log_path = f'./logs/Pyhidra_{args.project_name}_enhanced.log'
        else:
            # Fallback if context not loaded
            pyhidra_log_path = f'./logs/Pyhidra_{args.project_name}_enhanced.log'
    else:
        pyhidra_log_path = f'./logs/Pyhidra_{args.project_name}_enhanced.log'
    
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
        from collections import defaultdict
        
        # Open project
        try:
            project = GhidraProject.openProject(args.project_path, args.project_name, True)
            logging.info(f'Opened project: {project.project.name}')
        except IOException:
            logging.error(f'Could not open project {args.project_path}/{args.project_name}')
            return
        
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
        
        # Load ALL .fidb files at once
        logging.info("Loading all FID databases into memory...")
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
        
        logging.info(f"Successfully loaded {loaded_count} FID databases ({failed_count} failed)")
        
        # Verify loaded databases
        loaded_fid_files = FidFileManager.getInstance().getUserAddedFiles()
        logging.info(f"FidFileManager reports {len(loaded_fid_files)} active databases")
        
        # Results storage
        all_results = {}
        summary_by_version = {}
        
        # Search all programs in the project
        all_matches = {}
        match_num = []
        start_time = time.time()
        
        project_files = project.getRootFolder().getFiles()
        logging.info(f"Searching {len(project_files)} programs against {loaded_count} databases...")
        
        for file_ in project_files:
            name_ = file_.getName()
            logging.info(f"Searching {name_}...")
            
            program_ = project.openProgram('/', file_.getName(), True)
            
            # Search against ALL loaded FID databases simultaneously
            pmatches = search_fid_comprehensive(program_, monitor, nameAnalysis)
            
            if len(pmatches) != 0:
                match_num.append([name_, len(pmatches)])
                
                # Clean up name
                noheader_pos = name_.find('noheader')
                if noheader_pos != -1:
                    clean_name = name_[:noheader_pos]
                else:
                    clean_name = name_
                    
                all_matches[clean_name] = pmatches
                
                # Organize by version for compatibility with existing pipeline
                for parent in by_parent.keys():
                    if parent not in summary_by_version:
                        summary_by_version[parent] = {
                            'total_matches': 0,
                            'fid_count': len(by_parent[parent]),
                            'details': {}
                        }
                        all_results[parent] = {}
                    
                    # For enhanced search, we can't attribute matches to specific databases
                    # So we aggregate all matches under a combined entry
                    if 'all_databases' not in summary_by_version[parent]['details']:
                        summary_by_version[parent]['details']['all_databases'] = {
                            'count': len(pmatches),
                            'matches': pmatches
                        }
                        all_results[parent]['all_databases'] = {
                            'count': len(pmatches),
                            'matches': pmatches
                        }
                        summary_by_version[parent]['total_matches'] += len(pmatches)
            
            logging.info(f"{name_} matched {len(pmatches)} functions")
            project.close(program_)
        
        total_time = time.time() - start_time
        
        # Determine output directory
        if args.project_name.startswith('target_'):
            # Context should already be loaded from setup_logging
            try:
                res_dir = get_current_res_dir()
            except ValueError:
                # Fallback if no current analysis context
                import os
                os.makedirs('./res', exist_ok=True)
                res_dir = Path('./res')
        else:
            import os
            os.makedirs('./res', exist_ok=True)
            res_dir = Path('./res')
        
        # Save comprehensive results (compatible with existing pipeline)
        output_file = res_dir / f"FidSearchAll_{args.project_name}_{log_time}.json"
        with open(output_file, 'w') as f:
            json.dump({
                'project': args.project_name,
                'timestamp': log_time,
                'summary': summary_by_version,
                'detailed_results': all_results,
                'enhanced_search': True,
                'databases_loaded': loaded_count
            }, f, indent=2)
        
        # Save summary CSV (compatible with existing pipeline)
        csv_file = res_dir / f"FidSearchAll_{args.project_name}_{log_time}_summary.csv"
        with open(csv_file, 'w') as f:
            f.write("Version,Total_Matches,FID_Files_Checked\n")
            for version, data in summary_by_version.items():
                f.write(f"{version},{data['total_matches']},{data['fid_count']}\n")
        
        # Save individual program matches
        program_file = res_dir / f"FidSearchAll_{args.project_name}_{log_time}_programs.csv"
        with open(program_file, 'w') as f:
            f.write("Program,Matches,MatchesPerSecond\n")
            for i in match_num:
                matches_per_sec = i[1] / total_time if total_time > 0 else 0
                f.write(f'{i[0]},{i[1]},{matches_per_sec:.2f}\n')
        
        # Enhanced statistics
        total_matches = sum(len(matches) for matches in all_matches.values())
        avg_matches = total_matches / len(all_matches) if all_matches else 0
        
        # Log summary (compatible with existing output)
        logging.info("\n=== ENHANCED FID SEARCH SUMMARY ===")
        if summary_by_version:
            best_version = max(summary_by_version.items(), key=lambda x: x[1]['total_matches'])
            logging.info(f"Best matching version: {best_version[0]} with {best_version[1]['total_matches']} matches")
        
        for version, data in sorted(summary_by_version.items(), key=lambda x: x[1]['total_matches'], reverse=True):
            logging.info(f"{version}: {data['total_matches']} matches from {data['fid_count']} FID files")
        
        logging.info(f"\nPrograms searched: {len(project_files)}")
        logging.info(f"Programs with matches: {len(all_matches)}")
        logging.info(f"Total function matches: {total_matches}")
        logging.info(f"Average matches per program: {avg_matches:.1f}")
        logging.info(f"FID databases loaded: {loaded_count}")
        logging.info(f"Search time: {total_time:.2f}s")
        logging.info(f"Performance: {total_matches/total_time:.1f} matches/second")
        
        logging.info(f"\nResults saved to: {output_file}")
        logging.info(f"Summary saved to: {csv_file}")
        logging.info(f"Program details: {program_file}")
        
        project.close()
        
    except Exception as e:
        logging.error(f"Enhanced FID search failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()