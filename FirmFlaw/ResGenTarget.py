import logging 
import argparse 
import time 
import os
import json
from pathlib import Path
from utils.sample_folders import get_current_res_dir, load_current_context, get_current_logs_dir

threshold = 2
log_time = time.strftime("%m_%d_%H_%M")

def md_table(row, col, data, float_=False):
    '''
    construct markdown table 
    float_: use float in table 
    '''
    if len(data) != len(row) or len(data[0]) != len(col):
        logging.error(f'Error: data:{data} not match row:{row} col:{col}')
    str_ = "| "
    split_ = "|-"
    for i in col:
        str_ += "|" + i
        split_ += "|-"
    str_ += "|\n" + split_ + "|\n"
    for (idx,item) in enumerate(row):
        str_ += "|" + item
        for j in data[idx]:
            if float_:
                str_ += f"| {j:.2f}"
            else:
                str_ += f"| {j}"
        str_ += "|\n"
    return str_

def best_match(prefix, ext):
    '''
    select the best match result from multiple run
    using prefix string and extension based on file size 
    '''
    # Use current sample res directory for target analysis
    try:
        res_dir = get_current_res_dir()
    except ValueError:
        # Fallback if no current analysis context
        res_dir = Path('./res')
    
    max_size = 0
    match_ = None 
    for i in os.listdir(res_dir):
        if not i.startswith(prefix) or not i.endswith(ext):
            continue
        path_ = res_dir / i
        size_ = os.path.getsize(path_)
        if size_ > max_size:
            max_size = size_
            match_ = path_
    if match_ is None:
        logging.error(f"Error: no match file with prefix {prefix}")
        return None
    return match_

def target_analysis():
    '''
    Analyze the target firmware results
    '''
    target_info = {}
    
    # Use current sample res directory for target analysis
    try:
        res_dir = get_current_res_dir()
    except ValueError:
        # Fallback if no current analysis context
        res_dir = Path('./res')
    
    # Find target CSV file
    target_csv = None
    for f in os.listdir(res_dir):
        if f.startswith('func_num_target_') and f.endswith('.csv'):
            target_csv = res_dir / f
            break
    
    if target_csv and os.path.exists(target_csv):
        with open(target_csv) as file:
            lines = file.readlines()
        if len(lines) > 1:
            data = lines[1].split(',')
            if len(data) >= 5:
                target_info['name'] = data[0].strip()
                try:
                    target_info['handlers'] = int(data[1])
                except ValueError:
                    target_info['handlers'] = 0
                try:
                    target_info['functions'] = int(data[2])
                except ValueError:
                    target_info['functions'] = 0
                # Handle None or invalid size values
                size_str = data[3].strip()
                if size_str and size_str.lower() != 'none':
                    try:
                        target_info['size'] = int(size_str) / 1024  # Convert to KB
                    except ValueError:
                        target_info['size'] = 0
                else:
                    target_info['size'] = 0
                try:
                    target_info['analysis_time'] = int(data[4])
                except ValueError:
                    target_info['analysis_time'] = 0
    
    return target_info

def target_matches():
    '''
    Get match results for target firmware
    '''
    results = {}
    
    # FunctionID matches
    fid_file = best_match('FidSearchAll_target', '_summary.csv')
    if fid_file:
        with open(fid_file, 'r') as file:
            lines = file.readlines()
        fid_matches = 0
        for line in lines[1:]:
            parts = line.split(',')
            if len(parts) >= 2:
                fid_matches += int(parts[1])
        results['FunctionID'] = fid_matches
    
    # SimMatch results
    sim_file = best_match('SimMatch_binfunc_target', '_statistic.csv')
    if sim_file:
        with open(sim_file, 'r') as file:
            lines = file.readlines()
        sim_matches = 0
        for line in lines[1:]:
            parts = line.split(',')
            if len(parts) >= 2:
                sim_matches += int(parts[1])
        results['SimMatch'] = sim_matches
    
    return results

def mitigation_detection():
    '''
    Check mitigation methods in target firmware
    '''
    mpu_num = 0
    trustzone_num = 0
    
    # Check for MPU file
    mpu_file = best_match('MPU_target', '.csv')
    if mpu_file and os.path.exists(mpu_file):
        with open(mpu_file, 'r') as file:
            lines = file.readlines()
        mpu_num = len(lines) - 1  # -1 for header
    
    # Check for SMPU file
    smpu_file = best_match('SMPU_target', '.csv')
    if smpu_file and os.path.exists(smpu_file):
        with open(smpu_file, 'r') as file:
            lines = file.readlines()
        mpu_num += len(lines) - 1
    
    # Check for trustzone file
    trustzone_s_file = best_match('trustzone_s_target', '.csv')
    if trustzone_s_file and os.path.exists(trustzone_s_file):
        with open(trustzone_s_file, 'r') as file:
            lines = file.readlines()
        trustzone_num = len(lines) - 1
    
    return {'MPU': mpu_num, 'TrustZone': trustzone_num}

def main(args):
    global threshold
    threshold = args.threshold
    
    md_ = "# Target Firmware Analysis Results\n\n"
    
    # Target information
    target_info = target_analysis()
    if target_info:
        md_ += "## Target Firmware Information\n\n"
        md_ += f"- **Firmware**: {target_info.get('name', 'Unknown')}\n"
        md_ += f"- **Functions**: {target_info.get('functions', 0)}\n"
        md_ += f"- **Handlers**: {target_info.get('handlers', 0)}\n"
        md_ += f"- **Size**: {target_info.get('size', 0):.2f} KB\n"
        md_ += f"- **Analysis Time**: {target_info.get('analysis_time', 0)} seconds\n\n"
    
    # Match results
    md_ += "## Function Matching Results\n\n"
    matches = target_matches()
    if matches:
        match_table = md_table(['FunctionID', 'SimMatch'], ['Matches Found'], [
            [matches.get('FunctionID', 0)],
            [matches.get('SimMatch', 0)]
        ])
        md_ += match_table + "\n"
    else:
        md_ += "No match results found.\n\n"
    
    # Mitigation detection
    md_ += "## Security Mitigation Detection\n\n"
    mitigations = mitigation_detection()
    if mitigations['MPU'] > 0 or mitigations['TrustZone'] > 0:
        md_ += f"- **MPU Functions**: {mitigations['MPU']}\n"
        md_ += f"- **TrustZone Functions**: {mitigations['TrustZone']}\n\n"
    else:
        md_ += "No security mitigation methods detected.\n\n"
    
    # Write results
    try:
        res_dir = get_current_res_dir()
        output_file = res_dir / 'target_analysis_results.md'
    except ValueError:
        # Fallback if no current analysis context
        output_file = './res/target_analysis_results.md'
    
    with open(output_file, 'w') as file:
        file.write(md_)
    
    print(f"Results written to: {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Generate analysis results for target firmware")
    parser.add_argument("threshold", type=int, default=2, 
                       help="the threshold of match times to generate library adoption")
    args = parser.parse_args()
    
    # Setup logging
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
    
    # Load analysis context first (for target analysis)
    if load_current_context():
        try:
            logs_dir = get_current_logs_dir()
            log_filename = logs_dir / f'ResGenTarget_{log_time}.log'
        except ValueError:
            # Fallback if no current analysis context
            os.makedirs('./logs', exist_ok=True)
            log_filename = f'./logs/ResGenTarget_{log_time}.log'
    else:
        # Fallback if context not loaded
        os.makedirs('./logs', exist_ok=True)
        log_filename = f'./logs/ResGenTarget_{log_time}.log'
    
    logging.basicConfig(
        filename=str(log_filename), 
        level=logging.DEBUG, 
        format=LOG_FORMAT, 
        datefmt=DATE_FORMAT
    )
    
    try:
        main(args)
    except KeyboardInterrupt:
        logging.error("Exit with keyboard")
    except Exception as e:
        logging.error(f"Error: {e}")
        raise