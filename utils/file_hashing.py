
#!/usr/bin/env python3
# File hashing utilities

import hashlib
import logging
import os

logger = logging.getLogger("RansomEye.FileHashing")

def hash_file(file_path, algorithm='sha256', block_size=65536):
    """
    Calculate hash of a file using specified algorithm.
    
    Parameters:
        file_path (str): Path to the file
        algorithm (str): Hashing algorithm (md5, sha1, sha256)
        block_size (int): Size of blocks to read at once
        
    Returns:
        str: Hexadecimal hash digest
    """
    try:
        # Select hash algorithm
        if algorithm.lower() == 'md5':
            file_hash = hashlib.md5()
        elif algorithm.lower() == 'sha1':
            file_hash = hashlib.sha1()
        else:  # Default to SHA-256
            file_hash = hashlib.sha256()
        
        # Check if file exists
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            logger.warning(f"File not accessible for hashing: {file_path}")
            return "FILE_NOT_ACCESSIBLE"
        
        # Read file in chunks and update hash
        with open(file_path, 'rb') as f:
            buffer = f.read(block_size)
            while len(buffer) > 0:
                file_hash.update(buffer)
                buffer = f.read(block_size)
        
        return file_hash.hexdigest()
        
    except PermissionError:
        logger.warning(f"Permission denied when hashing file: {file_path}")
        return "PERMISSION_DENIED"
    except FileNotFoundError:
        logger.warning(f"File not found when hashing: {file_path}")
        return "FILE_NOT_FOUND"
    except Exception as e:
        logger.error(f"Error hashing file {file_path}: {e}")
        return "HASH_ERROR"

def hash_data(data, algorithm='sha256'):
    """
    Calculate hash of data using specified algorithm.
    
    Parameters:
        data (bytes): Data to hash
        algorithm (str): Hashing algorithm (md5, sha1, sha256)
        
    Returns:
        str: Hexadecimal hash digest
    """
    try:
        # Select hash algorithm
        if algorithm.lower() == 'md5':
            data_hash = hashlib.md5()
        elif algorithm.lower() == 'sha1':
            data_hash = hashlib.sha1()
        else:  # Default to SHA-256
            data_hash = hashlib.sha256()
        
        # Update hash with data
        data_hash.update(data)
        
        return data_hash.hexdigest()
        
    except Exception as e:
        logger.error(f"Error hashing data: {e}")
        return "HASH_ERROR"
