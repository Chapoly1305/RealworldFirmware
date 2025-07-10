#!/bin/bash
set -e

green="\033[32m"
red="\033[31m"
reset="\033[0m"

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
    python3 run_parallel_complete.py firmware_match "$MATCH_BASE" --fresh
else
    # Build database and match target
    if [ ! -f "$TARGET_FILE" ]; then
        echo "${red}Error: Target file '$TARGET_FILE' not found${reset}"
        exit 1
    fi
    python3 run_parallel_complete.py firmware_match "$MATCH_BASE" --fresh --target "$TARGET_FILE"
fi

# If target was provided, also run additional analyses
if [ ! -z "$TARGET_FILE" ]; then
    TARGET_NAME="target_$(basename ${TARGET_FILE%.*})"
    
    # Mitigation Method check
    echo "${green}Mitigation Method Detection for target${reset}"
    python3 Mitigation.py ./ghidra_projects "$TARGET_NAME"
    
    # Generate results
    echo "${green}Generate Final Results${reset}"
    python3 ResGen.py
    
    echo "${green}Finish! Check results in ./res/${reset}"
    echo "- FID results: ./res/FidSearchAll_${TARGET_NAME}_*.json"
    echo "- SimMatch results: ./res/SimMatch_*.json"
    echo "- Summary: ./res/results.md"
else
    echo "${green}Match database built successfully!${reset}"
    echo "Database location: ./db/binfunc_firmware_match.db"
    echo "FID files: ./fidb/"
    echo ""
    echo "To match a target firmware, run:"
    echo "  $0 $MATCH_BASE <target_firmware>"
fi
