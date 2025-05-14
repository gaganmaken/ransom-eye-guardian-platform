
#!/usr/bin/env python3
# Auto-Mitigation Engine for RansomEye

import os
import time
import logging
import subprocess
import signal
import json
import shutil
from datetime import datetime

logger = logging.getLogger("RansomEye.Mitigation")

class Mitigation:
    def __init__(self, db_writer, auto_mitigate=False):
        self.db_writer = db_writer
        self.auto_mitigate = auto_mitigate
        self.quarantine_dir = os.path.join('data', 'quarantine')
        
        # Create quarantine directory if it doesn't exist
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        # Track mitigations to avoid duplicates
        self.mitigated_files = set()
        self.mitigated_processes = set()
        self.mitigated_networks = set()
        
        # Escalation counter
        self.escalation_count = 0
        self.last_escalation_time = time.time()
    
    def handle_file_threat(self, file_path, event_id):
        """Handle a file-based threat"""
        if file_path in self.mitigated_files:
            return
            
        try:
            logger.warning(f"Mitigating file threat: {file_path}")
            
            # Track that we've dealt with this file
            self.mitigated_files.add(file_path)
            
            if self.auto_mitigate:
                # Quarantine the file
                self._quarantine_file(file_path)
                
                # Update database with mitigation action
                self.db_writer.update_file_event_action(
                    event_id, 
                    action_taken="quarantined"
                )
                
                # Update event as mitigated
                self.db_writer.update_event_mitigated(event_id, True)
                
                logger.info(f"File {file_path} quarantined successfully")
            else:
                # Log that mitigation would have occurred
                logger.info(f"Auto-mitigation disabled. Would have quarantined: {file_path}")
                
        except Exception as e:
            logger.error(f"Error mitigating file threat {file_path}: {e}")
    
    def handle_process_threat(self, pid, process_name, command_line, event_id):
        """Handle a process-based threat"""
        if pid in self.mitigated_processes:
            return
            
        try:
            logger.warning(f"Mitigating process threat: {pid} ({process_name})")
            
            # Track that we've dealt with this process
            self.mitigated_processes.add(pid)
            
            if self.auto_mitigate:
                # Terminate the process
                self._terminate_process(pid)
                
                # Update database with mitigation action
                self.db_writer.update_process_event_action(
                    event_id, 
                    action_taken="terminated"
                )
                
                # Update event as mitigated
                self.db_writer.update_event_mitigated(event_id, True)
                
                logger.info(f"Process {pid} ({process_name}) terminated successfully")
            else:
                # Log that mitigation would have occurred
                logger.info(f"Auto-mitigation disabled. Would have terminated process: {pid}")
                
        except Exception as e:
            logger.error(f"Error mitigating process threat {pid}: {e}")
    
    def handle_network_threat(self, src_ip, dst_ip, src_port, dst_port, event_id):
        """Handle a network-based threat"""
        conn_tuple = (src_ip, dst_ip, src_port, dst_port)
        if conn_tuple in self.mitigated_networks:
            return
            
        try:
            logger.warning(f"Mitigating network threat: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
            # Track that we've dealt with this connection
            self.mitigated_networks.add(conn_tuple)
            
            if self.auto_mitigate:
                # Block the connection using iptables/ufw
                self._block_connection(src_ip, dst_ip, dst_port)
                
                # Update database with mitigation action
                self.db_writer.update_network_event_action(
                    event_id, 
                    action_taken="blocked"
                )
                
                # Update event as mitigated
                self.db_writer.update_event_mitigated(event_id, True)
                
                logger.info(f"Network connection {src_ip}->{dst_ip}:{dst_port} blocked successfully")
            else:
                # Log that mitigation would have occurred
                logger.info(f"Auto-mitigation disabled. Would have blocked connection: {src_ip}->{dst_ip}:{dst_port}")
                
        except Exception as e:
            logger.error(f"Error mitigating network threat {src_ip}->{dst_ip}: {e}")
    
    def escalate_threat(self, reason, severity=9, source="mitigation"):
        """Escalate a severe threat - take more drastic measures"""
        try:
            # Avoid too frequent escalations
            current_time = time.time()
            if current_time - self.last_escalation_time < 60:  # At most one escalation per minute
                return
                
            self.last_escalation_time = current_time
            self.escalation_count += 1
            
            logger.critical(f"THREAT ESCALATION ({self.escalation_count}): {reason}")
            
            # Record escalation in database
            event_id = self.db_writer.add_event(
                event_type="threat_escalation",
                severity=severity,
                source=source,
                description=f"Threat escalation: {reason}"
            )
            
            # Take emergency actions if auto-mitigation is enabled
            if self.auto_mitigate:
                if self.escalation_count >= 3:
                    # Extreme measures for repeated escalations
                    logger.critical("CRITICAL THREAT LEVEL: Taking emergency isolation measures")
                    self._emergency_isolation()
                
        except Exception as e:
            logger.error(f"Error during threat escalation: {e}")
    
    def _quarantine_file(self, file_path):
        """Move a file to quarantine"""
        try:
            if not os.path.exists(file_path):
                logger.warning(f"File not found for quarantine: {file_path}")
                return False
            
            # Create a safe filename for quarantine
            safe_name = file_path.replace("/", "_").replace("\\", "_")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_path = os.path.join(self.quarantine_dir, f"{timestamp}_{safe_name}")
            
            # Copy file metadata
            file_info = {
                "original_path": file_path,
                "quarantine_time": timestamp,
                "size": os.path.getsize(file_path),
                "permissions": oct(os.stat(file_path).st_mode)[-3:]
            }
            
            # Save metadata
            meta_path = f"{quarantine_path}.meta"
            with open(meta_path, 'w') as f:
                json.dump(file_info, f)
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {e}")
            return False
    
    def _terminate_process(self, pid):
        """Terminate a process by PID"""
        try:
            # First try SIGTERM for graceful termination
            os.kill(int(pid), signal.SIGTERM)
            
            # Wait a moment
            time.sleep(0.5)
            
            # Check if process is still running
            try:
                os.kill(int(pid), 0)  # Signal 0 is used to check if process exists
                
                # If we get here, process still exists; use SIGKILL
                os.kill(int(pid), signal.SIGKILL)
                logger.info(f"Process {pid} forcefully terminated with SIGKILL")
            except OSError:
                # Process already terminated
                logger.info(f"Process {pid} terminated gracefully")
                
            return True
            
        except Exception as e:
            logger.error(f"Error terminating process {pid}: {e}")
            return False
    
    def _block_connection(self, src_ip, dst_ip, dst_port):
        """Block a network connection using iptables"""
        try:
            # Try using UFW (Uncomplicated Firewall) first if available
            if self._check_command_exists("ufw"):
                # Block outgoing connection to destination
                cmd = ["sudo", "ufw", "deny", "out", "from", "any", "to", f"{dst_ip}"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    logger.info(f"Blocked connection to {dst_ip} using UFW")
                    return True
            
            # Fallback to iptables
            if self._check_command_exists("iptables"):
                # Block outgoing traffic to suspicious destination
                cmd = ["sudo", "iptables", "-A", "OUTPUT", "-d", f"{dst_ip}", "-j", "DROP"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    logger.info(f"Blocked connection to {dst_ip} using iptables")
                    return True
            
            logger.warning("Failed to block connection - neither UFW nor iptables available")
            return False
            
        except Exception as e:
            logger.error(f"Error blocking connection to {dst_ip}: {e}")
            return False
    
    def _emergency_isolation(self):
        """Emergency isolation mode - disconnect network and freeze system"""
        try:
            logger.critical("EMERGENCY ISOLATION: Disconnecting network interfaces")
            
            # Record emergency action
            self.db_writer.add_event(
                event_type="emergency_isolation",
                severity=10,
                source="mitigation",
                description="Emergency isolation mode activated"
            )
            
            # Try to disconnect network using IP command (modern approach)
            if self._check_command_exists("ip"):
                # Get all interfaces
                result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
                
                # Parse interfaces (very simple parsing)
                interfaces = []
                for line in result.stdout.splitlines():
                    if ":" in line and "state" in line.lower():
                        # Extract interface name (between number and colon)
                        parts = line.split(":", 2)
                        if len(parts) >= 2:
                            iface = parts[1].strip()
                            if iface != "lo":  # Skip loopback
                                interfaces.append(iface)
                
                # Disconnect each interface
                for iface in interfaces:
                    subprocess.run(["sudo", "ip", "link", "set", iface, "down"], 
                                 capture_output=True)
                    logger.critical(f"Disconnected network interface: {iface}")
            
            # Fallback to ifconfig if ip command not available
            elif self._check_command_exists("ifconfig"):
                # Get all interfaces
                result = subprocess.run(["ifconfig"], capture_output=True, text=True)
                
                # Parse interfaces (very simple parsing)
                interfaces = []
                for line in result.stdout.splitlines():
                    if line and not line.startswith(" ") and ":" in line:
                        iface = line.split(":", 1)[0].strip()
                        if iface != "lo":  # Skip loopback
                            interfaces.append(iface)
                
                # Disconnect each interface
                for iface in interfaces:
                    subprocess.run(["sudo", "ifconfig", iface, "down"], capture_output=True)
                    logger.critical(f"Disconnected network interface: {iface}")
            
            else:
                logger.error("Failed to disconnect network - neither ip nor ifconfig command available")
                
        except Exception as e:
            logger.error(f"Error during emergency isolation: {e}")
    
    def _check_command_exists(self, cmd):
        """Check if a command exists in the system PATH"""
        return subprocess.run(["which", cmd], capture_output=True).returncode == 0
