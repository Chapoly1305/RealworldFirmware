#!/bin/bash
set -e

green=$'\033[32m'
red=$'\033[31m'
reset=$'\033[0m'

if [ $# -eq 0 ]; then
    echo "Usage: $0 <match_base_dir> [target_firmware]"
    echo "Examples:"
    echo "  $0 ./match_base              # Build match database only"
    echo "  $0 ./match_base firmware.bin  # Build database and match target"
    exit 0
fi

MATCH_BASE=$1
TARGET_FILE=$2

# prepare environments 
./prepare.sh

# Build match database
echo "${green}Building match database from: $MATCH_BASE${reset}"
if [ -z "$TARGET_FILE" ]; then
    # Just build database
    python3 run_parallel_complete.py firmware_match "$MATCH_BASE"
else
    # Build database and match target
    if [ ! -f "$TARGET_FILE" ]; then
        echo "${red}Error: Target file '$TARGET_FILE' not found${reset}"
        exit 1
    fi
    python3 run_parallel_complete.py firmware_match "$MATCH_BASE" --target "$TARGET_FILE"
fi

# If target was provided, also run additional analyses
if [ ! -z "$TARGET_FILE" ]; then
    TARGET_NAME="target_$(basename ${TARGET_FILE%.*})"
    
    # Mitigation Method check
    echo "${green}Mitigation Method Detection for target${reset}"
    python3 Mitigation.py ./ghidra_projects "$TARGET_NAME"
    
    # Merge CSV fragments
    echo "${green}Merging CSV results${reset}"
    python3 merge_csv_results.py -y
    
    # Generate results
    echo "${green}Generate Final Results${reset}"
    python3 ResGenTarget.py 2
    
    echo "${green}Finish! Results are organized in sample-specific folders${reset}"
    echo "- Check ./results/${TARGET_NAME}_* for analysis results"
    echo "- FID results: FidSearchAll_${TARGET_NAME}_*.json"
    echo "- SimMatch results: SimMatch_*.json"
    echo "- Summary: target_analysis_results.md"
else
    # Merge CSV fragments for match database
    echo "${green}Merging CSV results${reset}"
    python3 merge_csv_results.py -y
    
    echo "${green}Match database built successfully!${reset}"
    echo "Database location: ./db/binfunc_firmware_match.db"
    echo "FID files: ./fidb/"
    echo ""
    echo "To match a target firmware, run:"
    echo "  $0 $MATCH_BASE <target_firmware>"
fi
