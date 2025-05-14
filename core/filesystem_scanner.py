
#!/usr/bin/env python3
# Filesystem Scanner Module for RansomEye

import os
import time
import logging
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from utils.entropy_calc import calculate_file_entropy
from utils.file_hashing import hash_file

logger = logging.getLogger("RansomEye.FilesystemScanner")

class FilesystemEventHandler(FileSystemEventHandler):
    def __init__(self, scanner):
        self.scanner = scanner
        super().__init__()
    
    def on_modified(self, event):
        if not event.is_directory:
            self.scanner.check_file(event.src_path)
    
    def on_created(self, event):
        if not event.is_directory:
            self.scanner.check_file(event.src_path)
    
    def on_moved(self, event):
        if not event.is_directory:
            # Check for typical ransomware extensions
            dest_path = event.dest_path
            if any(dest_path.endswith(ext) for ext in self.scanner.SUSPICIOUS_EXTENSIONS):
                self.scanner.record_suspicious_rename(event.src_path, dest_path)

class FilesystemScanner:
    # Suspicious file extensions typically used by ransomware
    SUSPICIOUS_EXTENSIONS = [
        '.encrypted', '.enc', '.locked', '.crypto', '.crypt', '.crypted',
        '.cryp', '.crypt', '.cryptolocker', '.cryptowall', '.exx', '.ezz',
        '.locky', '.xtbl', '.crypt', '.cerber', '.cerber3', '.crypz', '.crpt', 
        '.vault', '.zzz', '.wncry', '.wannacry', '.wcry', '.wncrypt', '.onion',
        '.wallet', '.globe', '.hair', '.breaking_bad', '.ryuk', '.locked',
    ]
    
    # Directories to monitor closely
    CRITICAL_DIRECTORIES = [
        '/home', '/var/www', '/var/log', '/opt', '/srv',
        '/etc', '/usr/local', '/root'
    ]
    
    # Directories to exclude from monitoring to reduce noise
    EXCLUDED_DIRECTORIES = [
        '/proc', '/sys', '/dev', '/run', '/tmp', '/var/cache',
        '/var/tmp', '/lost+found', '/media', '/mnt'
    ]
    
    def __init__(self, db_writer, anomaly_engine, mitigation, 
                 entropy_threshold=7.8, scan_interval=60):
        self.db_writer = db_writer
        self.anomaly_engine = anomaly_engine
        self.mitigation = mitigation
        self.entropy_threshold = entropy_threshold
        self.scan_interval = scan_interval
        self.observers = []
        self.recent_changes = {}  # To track rapid changes
        self.rename_count = 0  # Counter for suspicious renames
        
    def start_monitoring(self):
        """Start monitoring the filesystem for changes"""
        try:
            # Start watchdog observers for critical directories
            event_handler = FilesystemEventHandler(self)
            
            for directory in self.CRITICAL_DIRECTORIES:
                if os.path.exists(directory):
                    observer = Observer()
                    observer.schedule(event_handler, directory, recursive=True)
                    observer.start()
                    self.observers.append(observer)
                    logger.info(f"Started monitoring directory: {directory}")
            
            # Perform periodic full scans
            while True:
                logger.info("Performing periodic scan...")
                self.perform_full_scan()
                time.sleep(self.scan_interval)
                
        except Exception as e:
            logger.error(f"Error in filesystem monitoring: {e}")
            
        finally:
            for observer in self.observers:
                observer.stop()
            for observer in self.observers:
                observer.join()
    
    def check_file(self, file_path):
        """Check a single file for suspicious characteristics"""
        try:
            # Skip excluded directories
            if any(file_path.startswith(excl) for excl in self.EXCLUDED_DIRECTORIES):
                return
            
            # Skip very large files
            try:
                if os.path.getsize(file_path) > 50 * 1024 * 1024:  # Skip files > 50MB
                    return
            except (FileNotFoundError, PermissionError):
                return
            
            # Check if file has suspicious extension
            if any(file_path.endswith(ext) for ext in self.SUSPICIOUS_EXTENSIONS):
                self.record_suspicious_file(file_path, reason="Suspicious extension")
                return
            
            # Calculate entropy to detect encrypted files
            try:
                entropy = calculate_file_entropy(file_path)
                if entropy > self.entropy_threshold:
                    file_hash = hash_file(file_path)
                    self.record_suspicious_file(file_path, reason=f"High entropy ({entropy:.2f})", 
                                               file_hash=file_hash, entropy=entropy)
                    
                    # Send to anomaly engine for further analysis
                    self.anomaly_engine.analyze_file(file_path, entropy, file_hash)
            except (PermissionError, FileNotFoundError, IsADirectoryError):
                pass
                
            # Track rapid changes to detect mass encryption
            now = time.time()
            if file_path in self.recent_changes:
                time_diff = now - self.recent_changes[file_path]
                if time_diff < 5:  # Changed twice within 5 seconds
                    self.record_suspicious_file(file_path, reason="Rapid modifications")
            
            self.recent_changes[file_path] = now
            
        except Exception as e:
            logger.error(f"Error checking file {file_path}: {e}")
    
    def record_suspicious_file(self, file_path, reason, file_hash=None, entropy=None):
        """Record a suspicious file detection"""
        try:
            if file_hash is None:
                try:
                    file_hash = hash_file(file_path)
                except:
                    file_hash = "unknown"
            
            if entropy is None:
                try:
                    entropy = calculate_file_entropy(file_path)
                except:
                    entropy = 0.0
            
            logger.warning(f"Suspicious file detected: {file_path} - {reason}")
            
            # Insert event into database
            event_id = self.db_writer.add_event(
                event_type="suspicious_file",
                severity=8 if entropy > self.entropy_threshold else 6,
                source="filesystem_scanner",
                description=f"Suspicious file detected: {reason}"
            )
            
            # Record file details
            self.db_writer.add_file_event(
                event_id=event_id,
                file_path=file_path,
                file_hash=file_hash,
                entropy=entropy,
                action_taken="detected"
            )
            
            # Consider mitigation
            self.mitigation.handle_file_threat(file_path, event_id)
            
        except Exception as e:
            logger.error(f"Error recording suspicious file {file_path}: {e}")
    
    def record_suspicious_rename(self, src_path, dest_path):
        """Record suspicious file rename operations"""
        try:
            self.rename_count += 1
            
            logger.warning(f"Suspicious file rename: {src_path} -> {dest_path}")
            
            # Insert event into database
            event_id = self.db_writer.add_event(
                event_type="suspicious_rename",
                severity=7,
                source="filesystem_scanner",
                description=f"Suspicious file rename to ransomware-like extension"
            )
            
            # Record file details
            self.db_writer.add_file_event(
                event_id=event_id,
                file_path=dest_path,
                file_hash="unknown",
                entropy=0.0,
                action_taken="detected"
            )
            
            # If many renames are happening, escalate
            if self.rename_count >= 5:
                logger.critical(f"Multiple suspicious renames detected ({self.rename_count})")
                self.db_writer.add_event(
                    event_type="mass_rename",
                    severity=9,
                    source="filesystem_scanner",
                    description=f"Multiple files renamed with suspicious extensions ({self.rename_count})"
                )
                
                # Consider mitigation
                self.mitigation.escalate_threat("Multiple suspicious file renames detected", 
                                              severity=9, source="filesystem_scanner")
        except Exception as e:
            logger.error(f"Error recording suspicious rename {src_path}: {e}")
    
    def perform_full_scan(self):
        """Perform a full scan of critical directories"""
        # Reset counter each full scan
        self.rename_count = 0
        
        for directory in self.CRITICAL_DIRECTORIES:
            if not os.path.exists(directory):
                continue
                
            try:
                logger.info(f"Scanning directory: {directory}")
                for root, _, files in os.walk(directory):
                    # Skip excluded directories
                    if any(root.startswith(excl) for excl in self.EXCLUDED_DIRECTORIES):
                        continue
                        
                    for file in files:
                        file_path = os.path.join(root, file)
                        # Check for suspicious extensions
                        if any(file.endswith(ext) for ext in self.SUSPICIOUS_EXTENSIONS):
                            self.record_suspicious_file(file_path, reason="Suspicious extension")
            except Exception as e:
                logger.error(f"Error scanning {directory}: {e}")
