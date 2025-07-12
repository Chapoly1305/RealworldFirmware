import os 
import time
import json
import logging
import argparse
from pathlib import Path
from utils.db import *
from utils.key import *
from utils.match import *
from utils.sample_folders import get_current_res_dir, get_current_logs_dir, load_current_context
from tqdm import tqdm,trange

log_time = time.strftime("%m_%d_%H_%M")

def timeout_handler(signum, frame):
    raise TimeoutError("Timed out!")

def main(args):
    conn = sqlite3.connect(args.input_db)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM func_table')
    # test
    #cursor.execute("SELECT COUNT(*) FROM func_table WHERE program LIKE 'bcf%'")
    result_len = cursor.fetchone()[0]

    conn1 = sqlite3.connect(args.database)
    cursor1 = conn1.cursor()

    cursor.execute('SELECT * FROM func_table') # test 
    #cursor.execute("SELECT * FROM func_table WHERE program LIKE 'bcf%'")
    all_results = {}
    max_results = {}
    start_time = time.time()
    for i in trange(result_len):
        result_ = cursor.fetchone()
        if result_ is None:
            logging.error("Result is None")
            tqdm.write(f'wrong')
            break 
        # del the id 
        result_ = result_[1:]
        name_ = result_[func_key_idx('name')]
        program_ = result_[func_key_idx('program')]
        (max_, matches_, time1, time2, len1, len2) = compare_func_db_time(cursor1, result_)
        if len2 > 0:
            logging.debug(f"{name_} with {result_[func_key_idx('numAddresses')]} addr at {program_} match {len2} first stage len {len1}")
        if len(matches_) > 0:
            if all_results.get(program_) is None:
                all_results[program_] = {}
                max_results[program_] = {}
            match_result_ = []
            for match_ in matches_:
                # only add func name and program name and numAddresses and ratio to result_
                match_result_.append([match_[0][0],match_[0][1],match_[0][3],match_[1]])
            all_results[program_][name_] = match_result_
            # max results 
            max_results[program_][name_] = {'name':max_[0][0],
                                        'program': max_[0][1],
                                        'numAddr': max_[0][3],
                                        'ratio': max_[1],
                                        'time1': time1,
                                        'time2': time2,
                                        'len1': len1,
                                        'len2': len2}
    conn.close()
    conn1.close()
    
    # Determine output directory - if input_db is a target, use sample-specific folder
    if 'target_' in str(args.input_db.name):
        # Try to load the context first
        if load_current_context():
            try:
                res_dir = get_current_res_dir()
            except ValueError:
                # Fallback if no current analysis context
                os.makedirs('./res', exist_ok=True)
                res_dir = Path('./res')
        else:
            # Fallback if context not loaded
            os.makedirs('./res', exist_ok=True)
            res_dir = Path('./res')
    else:
        os.makedirs('./res', exist_ok=True)
        res_dir = Path('./res')
    
    # write json 
    with open(res_dir / f'SimMatch_{args.input_db.name}_{args.database.name}_{log_time}.json', 'w') as file:
        json.dump(all_results, file, indent=4)
    with open(res_dir / f'SimMaxMatch_{args.input_db.name}_{args.database.name}_{log_time}.json', 'w') as file:
        json.dump(max_results, file, indent=4)
    # write csv 
    with open(res_dir / f'SimMatch_{args.input_db.name}_{log_time}_statistic.csv', 'w') as file:
        file.write(f'Program, Match Number\n')
        for (k,v) in max_results.items():
            file.write(f'{k},{len(v)}\n')
    # end
    logging.info(f"Finish: total annalysis time {time.time() - start_time}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Match similar functions based on database")
    parser.add_argument("input_db",type=Path, help="database need to be matched")
    parser.add_argument("database",type=Path, help="database to been matched")
    args = parser.parse_args()
    # log
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
    
    # Determine log path based on input database
    if 'target_' in str(args.input_db.name):
        # Try to load the context first
        if load_current_context():
            try:
                logs_dir = get_current_logs_dir()
                log_filename = logs_dir / f'SimMatch_{args.input_db.name}_{log_time}.log'
            except ValueError:
                # Fallback if no current analysis context
                os.makedirs('./logs', exist_ok=True)
                log_filename = f'./logs/SimMatch_{args.input_db.name}_{log_time}.log'
        else:
            # Fallback if context not loaded
            os.makedirs('./logs', exist_ok=True)
            log_filename = f'./logs/SimMatch_{args.input_db.name}_{log_time}.log'
    else:
        # Match database - use global logs directory
        os.makedirs('./logs', exist_ok=True)
        log_filename = f'./logs/SimMatch_{args.input_db.name}_{log_time}.log'
    
    # Get log level from environment variable, default to DEBUG
    log_level_str = os.environ.get('LOGLEVEL', 'DEBUG').upper()
    log_level = getattr(logging, log_level_str, logging.DEBUG)
    
    logging.basicConfig(filename=str(log_filename), level=log_level, format=LOG_FORMAT, datefmt=DATE_FORMAT)
    try:
        main(args)
    except KeyboardInterrupt:
        logging.error("Exit with keyboard")
        conn.close()
        conn1.close()
