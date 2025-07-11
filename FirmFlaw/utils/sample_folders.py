"""
Utility module for managing sample-specific folder structure.
Provides functions to create and manage organized output directories.
"""

import os
import time
from pathlib import Path
from datetime import datetime

def create_sample_folder(sample_name, timestamp=None):
    """
    Create a sample-specific folder with format: results/{sample_name}_{timestamp}/
    
    Args:
        sample_name (str): Name of the sample being analyzed
        timestamp (str, optional): Timestamp string. If None, current time is used.
    
    Returns:
        Path: Path to the created sample folder
    """
    if timestamp is None:
        timestamp = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
    
    folder_name = f"{sample_name}_{timestamp}"
    sample_dir = Path(f"./results/{folder_name}")
    
    # Create subdirectories
    (sample_dir / "res").mkdir(parents=True, exist_ok=True)
    (sample_dir / "logs").mkdir(parents=True, exist_ok=True)
    (sample_dir / "temp_analysis").mkdir(parents=True, exist_ok=True)
    (sample_dir / "db").mkdir(parents=True, exist_ok=True)
    
    return sample_dir

def get_sample_res_dir(sample_name, timestamp=None):
    """
    Get the res subdirectory path for a sample.
    
    Args:
        sample_name (str): Name of the sample being analyzed
        timestamp (str, optional): Timestamp string. If None, current time is used.
    
    Returns:
        Path: Path to the sample's res directory
    """
    sample_dir = create_sample_folder(sample_name, timestamp)
    return sample_dir / "res"

def get_sample_db_dir(sample_name, timestamp=None):
    """
    Get the db subdirectory path for a sample.
    
    Args:
        sample_name (str): Name of the sample being analyzed
        timestamp (str, optional): Timestamp string. If None, current time is used.
    
    Returns:
        Path: Path to the sample's db directory
    """
    sample_dir = create_sample_folder(sample_name, timestamp)
    return sample_dir / "db"

def get_sample_temp_dir(sample_name, timestamp=None):
    """
    Get the temp_analysis subdirectory path for a sample.
    
    Args:
        sample_name (str): Name of the sample being analyzed
        timestamp (str, optional): Timestamp string. If None, current time is used.
    
    Returns:
        Path: Path to the sample's temp_analysis directory
    """
    sample_dir = create_sample_folder(sample_name, timestamp)
    return sample_dir / "temp_analysis"

def get_sample_logs_dir(sample_name, timestamp=None):
    """
    Get the logs subdirectory path for a sample.
    
    Args:
        sample_name (str): Name of the sample being analyzed
        timestamp (str, optional): Timestamp string. If None, current time is used.
    
    Returns:
        Path: Path to the sample's logs directory
    """
    sample_dir = create_sample_folder(sample_name, timestamp)
    return sample_dir / "logs"

def cleanup_legacy_folders():
    """
    Clean up legacy res and temp_analysis folders if they are empty.
    """
    legacy_folders = ["./res", "./temp_analysis"]
    
    for folder in legacy_folders:
        folder_path = Path(folder)
        if folder_path.exists() and folder_path.is_dir():
            try:
                # Only remove if empty
                if not any(folder_path.iterdir()):
                    folder_path.rmdir()
                    print(f"Removed empty legacy folder: {folder}")
            except OSError:
                # Folder not empty or permission issue
                pass

# Global variables to store current analysis context
_current_sample_name = None
_current_timestamp = None

def set_current_analysis(sample_name, timestamp=None):
    """
    Set the current analysis context for this session.
    
    Args:
        sample_name (str): Name of the sample being analyzed
        timestamp (str, optional): Timestamp string. If None, current time is used.
    """
    global _current_sample_name, _current_timestamp
    _current_sample_name = sample_name
    if timestamp is None:
        timestamp = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
    _current_timestamp = timestamp

def get_current_sample_folder():
    """
    Get the current sample folder path based on set context.
    
    Returns:
        Path: Path to the current sample folder
        
    Raises:
        ValueError: If no current analysis context is set
    """
    if _current_sample_name is None:
        raise ValueError("No current analysis context set. Call set_current_analysis() first.")
    
    return create_sample_folder(_current_sample_name, _current_timestamp)

def get_current_res_dir():
    """Get current sample's res directory"""
    return get_current_sample_folder() / "res"

def get_current_db_dir():
    """Get current sample's db directory"""
    return get_current_sample_folder() / "db"

def get_current_temp_dir():
    """Get current sample's temp_analysis directory"""
    return get_current_sample_folder() / "temp_analysis"

def get_current_logs_dir():
    """Get current sample's logs directory"""
    return get_current_sample_folder() / "logs"