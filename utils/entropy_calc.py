
#!/usr/bin/env python3
# Entropy calculation utilities

import math
import logging
import os

logger = logging.getLogger("RansomEye.Entropy")

def calculate_file_entropy(file_path, block_size=8192, max_blocks=128):
    """
    Calculate the Shannon entropy of a file.
    
    Parameters:
        file_path (str): Path to the file
        block_size (int): Size of blocks to read
        max_blocks (int): Maximum number of blocks to read (to handle large files)
        
    Returns:
        float: Shannon entropy value between 0 and 8
    """
    try:
        # Check if file exists and is accessible
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            logger.warning(f"File not accessible for entropy calculation: {file_path}")
            return 0.0
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Skip empty files
        if file_size == 0:
            return 0.0
        
        # For very large files, read a sample
        bytes_to_read = min(file_size, block_size * max_blocks)
        
        # Initialize byte frequency counter
        byte_counters = [0] * 256
        
        # Read file in chunks for efficiency
        bytes_read = 0
        with open(file_path, 'rb') as f:
            while bytes_read < bytes_to_read:
                chunk = f.read(min(block_size, bytes_to_read - bytes_read))
                if not chunk:
                    break
                
                # Count byte frequencies
                for byte in chunk:
                    byte_counters[byte] += 1
                
                bytes_read += len(chunk)
        
        # Calculate entropy using Shannon's formula
        entropy = 0.0
        for count in byte_counters:
            if count > 0:
                probability = count / bytes_read
                entropy -= probability * math.log2(probability)
        
        return entropy
        
    except Exception as e:
        logger.error(f"Error calculating entropy for {file_path}: {e}")
        return 0.0

def is_high_entropy(entropy, threshold=7.8):
    """
    Check if entropy value is high (indicating potential encryption).
    
    Parameters:
        entropy (float): The calculated entropy value
        threshold (float): Threshold above which entropy is considered high
        
    Returns:
        bool: True if entropy is high, False otherwise
    """
    return entropy > threshold
