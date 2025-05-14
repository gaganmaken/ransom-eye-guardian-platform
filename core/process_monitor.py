
#!/usr/bin/env python3
# Process Monitor Module for RansomEye

import os
import time
import logging
import psutil
import re
from collections import defaultdict

logger = logging.getLogger("RansomEye.ProcessMonitor")

class ProcessMonitor:
    # Suspicious command patterns (regular expressions)
    SUSPICIOUS_CMD_PATTERNS = [
        # Command download and execution patterns
        r'curl\s+.+\s+\|\s+bash',
        r'wget\s+.+\s+\|\s+bash',
        r'curl\s+.+\s+\|\s+sh',
        r'wget\s+.+\s+\|\s+sh',
        # File permission changes followed by execution
        r'chmod\s+[+]?[rwx]{1,3}.*&&.*\./',
        # Encoded/obfuscated commands
        r'echo\s+[A-Za-z0-9+/=]+\s+\|\s+base64\s+--decode',
        r'bash\s+-c\s+.*base64',
        # Suspicious deletion commands
        r'rm\s+-[rf]{1,2}\s+/home',
        r'rm\s+-[rf]{1,2}\s+/var',
        r'rm\s+-[rf]{1,2}\s+.*backup',
        # Known malicious commands
        r'dd\s+if=/dev/urandom',
        r'shred\s+',
    ]
    
    # Suspicious process names
    SUSPICIOUS_PROCESS_NAMES = [
        'crpytohunter', 'miner', 'nspps', 'xmrig',
        'lolMiner', 'ethminer', 'nanominer'
    ]
    
    def __init__(self, db_writer, anomaly_engine, mitigation, cpu_threshold=80):
        self.db_writer = db_writer
        self.anomaly_engine = anomaly_engine
        self.mitigation = mitigation
        self.cpu_threshold = cpu_threshold
        self.process_history = {}  # Track process history
        self.suspicious_pids = set()  # Track already reported suspicious PIDs
        
    def start_monitoring(self):
        """Start monitoring processes"""
        try:
            logger.info("Process monitor started")
            
            while True:
                self.check_all_processes()
                time.sleep(2)  # Check every 2 seconds
                
        except Exception as e:
            logger.error(f"Error in process monitoring: {e}")
    
    def check_all_processes(self):
        """Scan all running processes for suspicious behavior"""
        try:
            # Record current time for performance monitoring
            start_time = time.time()
            
            # Get all running processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'username']):
                try:
                    # Skip if we've already flagged this process as suspicious
                    if proc.info['pid'] in self.suspicious_pids:
                        continue
                    
                    # Check for high CPU usage
                    if proc.info['cpu_percent'] > self.cpu_threshold:
                        # Wait and check again to avoid false positives
                        time.sleep(0.5)
                        proc.cpu_percent()
                        time.sleep(1)
                        if proc.cpu_percent() > self.cpu_threshold:
                            self.record_suspicious_process(proc, reason=f"High CPU usage: {proc.cpu_percent()}%")
                    
                    # Check process name
                    proc_name = proc.info['name'].lower() if proc.info['name'] else ""
                    if any(s_name in proc_name for s_name in self.SUSPICIOUS_PROCESS_NAMES):
                        self.record_suspicious_process(proc, reason=f"Suspicious process name: {proc_name}")
                    
                    # Check command line for suspicious patterns
                    cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
                    if cmdline:
                        for pattern in self.SUSPICIOUS_CMD_PATTERNS:
                            if re.search(pattern, cmdline):
                                self.record_suspicious_process(
                                    proc, 
                                    reason=f"Suspicious command pattern: {pattern}"
                                )
                                break
                    
                    # Check process ancestry
                    try:
                        process_tree = self.get_process_tree(proc.info['pid'])
                        if self.is_suspicious_process_tree(process_tree):
                            self.record_suspicious_process(
                                proc, 
                                reason="Suspicious process ancestry", 
                                process_tree=process_tree
                            )
                    except:
                        pass
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Check if scan took too long
            scan_duration = time.time() - start_time
            if scan_duration > 5:  # If scan took more than 5 seconds
                logger.warning(f"Process scan took too long: {scan_duration:.2f} seconds")
                
        except Exception as e:
            logger.error(f"Error checking processes: {e}")
    
    def get_process_tree(self, pid, depth=0, max_depth=5):
        """Get the ancestry tree of a process"""
        if depth >= max_depth:
            return []
        
        try:
            proc = psutil.Process(pid)
            cmd = " ".join(proc.cmdline()) if proc.cmdline() else proc.name()
            
            # Get parent recursively
            if proc.ppid() and proc.ppid() != pid:  # Avoid infinite loop
                parent_tree = self.get_process_tree(proc.ppid(), depth + 1, max_depth)
                return parent_tree + [cmd]
            else:
                return [cmd]
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return []
    
    def is_suspicious_process_tree(self, process_tree):
        """Check if a process tree is suspicious"""
        if not process_tree or len(process_tree) < 2:
            return False
        
        # Check for typical malicious patterns in process trees
        
        # Pattern: shell -> curl/wget -> chmod -> execution
        if any("curl" in cmd or "wget" in cmd for cmd in process_tree) and \
           any("chmod" in cmd for cmd in process_tree) and \
           any("./" in cmd for cmd in process_tree):
            return True
        
        # Pattern: base64 encoded execution
        if any("base64" in cmd for cmd in process_tree) and \
           any("bash" in cmd or "sh" in cmd for cmd in process_tree):
            return True
            
        # Pattern: sshd -> shell -> suspicious commands
        if any("sshd" in cmd for cmd in process_tree) and \
           any("bash" in cmd or "sh" in cmd for cmd in process_tree) and \
           any(re.search(pattern, cmd) for cmd in process_tree for pattern in self.SUSPICIOUS_CMD_PATTERNS):
            return True
        
        return False
    
    def record_suspicious_process(self, proc, reason, process_tree=None):
        """Record a suspicious process detection"""
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
            
            # Skip if already recorded
            if pid in self.suspicious_pids:
                return
                
            self.suspicious_pids.add(pid)
            
            if not process_tree:
                process_tree = self.get_process_tree(pid)
            
            process_tree_str = " -> ".join(process_tree)
            
            logger.warning(f"Suspicious process detected: {pid} ({name}) - {reason}")
            logger.debug(f"Command line: {cmdline}")
            logger.debug(f"Process tree: {process_tree_str}")
            
            # Determine severity based on the reason
            severity = 7
            if "High CPU" in reason:
                severity = 5
            elif "Suspicious command pattern" in reason:
                severity = 8
            elif "Suspicious process ancestry" in reason:
                severity = 9
            
            # Insert event into database
            event_id = self.db_writer.add_event(
                event_type="suspicious_process",
                severity=severity,
                source="process_monitor",
                description=f"Suspicious process detected: {reason}"
            )
            
            # Record process details
            parent_pid = proc.ppid() if hasattr(proc, 'ppid') else 0
            
            self.db_writer.add_process_event(
                event_id=event_id,
                pid=pid,
                process_name=name,
                command_line=cmdline,
                parent_pid=parent_pid,
                process_tree=process_tree_str,
                action_taken="detected"
            )
            
            # Send to anomaly engine for further analysis
            self.anomaly_engine.analyze_process(pid, name, cmdline, process_tree_str)
            
            # Consider mitigation
            if severity >= 8:
                self.mitigation.handle_process_threat(pid, name, cmdline, event_id)
                
        except Exception as e:
            logger.error(f"Error recording suspicious process: {e}")
