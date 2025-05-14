
#!/usr/bin/env python3
# Database Writer for RansomEye

import sqlite3
import logging
import threading
import time
from datetime import datetime

logger = logging.getLogger("RansomEye.DatabaseWriter")

class DatabaseWriter:
    def __init__(self, db_path):
        self.db_path = db_path
        self.lock = threading.Lock()
    
    def _get_connection(self):
        """Get a connection to the SQLite database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable dictionary access by column name
            return conn
        except Exception as e:
            logger.error(f"Error connecting to database: {e}")
            return None
    
    def add_event(self, event_type, severity, source, description):
        """Add a new event to the events table"""
        with self.lock:
            conn = self._get_connection()
            if not conn:
                return None
                
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO events 
                    (event_type, severity, source, description, timestamp) 
                    VALUES (?, ?, ?, ?, ?)
                    """, 
                    (event_type, severity, source, description, datetime.now().isoformat())
                )
                event_id = cursor.lastrowid
                conn.commit()
                return event_id
            except Exception as e:
                logger.error(f"Error adding event: {e}")
                return None
            finally:
                conn.close()
    
    def add_file_event(self, event_id, file_path, file_hash, entropy, action_taken):
        """Add a file event to the file_events table"""
        with self.lock:
            conn = self._get_connection()
            if not conn:
                return False
                
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO file_events 
                    (event_id, file_path, file_hash, entropy, action_taken) 
                    VALUES (?, ?, ?, ?, ?)
                    """, 
                    (event_id, file_path, file_hash, entropy, action_taken)
                )
                conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error adding file event: {e}")
                return False
            finally:
                conn.close()
    
    def add_process_event(self, event_id, pid, process_name, command_line, parent_pid, process_tree, action_taken):
        """Add a process event to the process_events table"""
        with self.lock:
            conn = self._get_connection()
            if not conn:
                return False
                
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO process_events 
                    (event_id, pid, process_name, command_line, parent_pid, process_tree, action_taken) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, 
                    (event_id, pid, process_name, command_line, parent_pid, process_tree, action_taken)
                )
                conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error adding process event: {e}")
                return False
            finally:
                conn.close()
    
    def add_network_event(self, event_id, source_ip, destination_ip, source_port, destination_port, protocol, packet_count, action_taken):
        """Add a network event to the network_events table"""
        with self.lock:
            conn = self._get_connection()
            if not conn:
                return False
                
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO network_events 
                    (event_id, source_ip, destination_ip, source_port, destination_port, protocol, packet_count, action_taken) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, 
                    (event_id, source_ip, destination_ip, source_port, destination_port, protocol, packet_count, action_taken)
                )
                conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error adding network event: {e}")
                return False
            finally:
                conn.close()
    
    def update_event_mitigated(self, event_id, mitigated):
        """Update an event's mitigation status"""
        with self.lock:
            conn = self._get_connection()
            if not conn:
                return False
                
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE events 
                    SET mitigated = ? 
                    WHERE id = ?
                    """, 
                    (1 if mitigated else 0, event_id)
                )
                conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error updating event mitigation: {e}")
                return False
            finally:
                conn.close()
    
    def update_file_event_action(self, event_id, action_taken):
        """Update a file event's action"""
        with self.lock:
            conn = self._get_connection()
            if not conn:
                return False
                
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE file_events 
                    SET action_taken = ? 
                    WHERE event_id = ?
                    """, 
                    (action_taken, event_id)
                )
                conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error updating file event action: {e}")
                return False
            finally:
                conn.close()
    
    def update_process_event_action(self, event_id, action_taken):
        """Update a process event's action"""
        with self.lock:
            conn = self._get_connection()
            if not conn:
                return False
                
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE process_events 
                    SET action_taken = ? 
                    WHERE event_id = ?
                    """, 
                    (action_taken, event_id)
                )
                conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error updating process event action: {e}")
                return False
            finally:
                conn.close()
    
    def update_network_event_action(self, event_id, action_taken):
        """Update a network event's action"""
        with self.lock:
            conn = self._get_connection()
            if not conn:
                return False
                
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE network_events 
                    SET action_taken = ? 
                    WHERE event_id = ?
                    """, 
                    (action_taken, event_id)
                )
                conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error updating network event action: {e}")
                return False
            finally:
                conn.close()
    
    def get_recent_events(self, limit=100):
        """Get recent events with their associated details"""
        with self.lock:
            conn = self._get_connection()
            if not conn:
                return []
                
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT * FROM events 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                    """, 
                    (limit,)
                )
                events = [dict(row) for row in cursor.fetchall()]
                
                # For each event, get associated details
                for event in events:
                    event_id = event['id']
                    
                    # Get file details if applicable
                    cursor.execute(
                        """
                        SELECT * FROM file_events 
                        WHERE event_id = ?
                        """, 
                        (event_id,)
                    )
                    file_events = cursor.fetchall()
                    if file_events:
                        event['file_details'] = [dict(row) for row in file_events]
                    
                    # Get process details if applicable
                    cursor.execute(
                        """
                        SELECT * FROM process_events 
                        WHERE event_id = ?
                        """, 
                        (event_id,)
                    )
                    process_events = cursor.fetchall()
                    if process_events:
                        event['process_details'] = [dict(row) for row in process_events]
                    
                    # Get network details if applicable
                    cursor.execute(
                        """
                        SELECT * FROM network_events 
                        WHERE event_id = ?
                        """, 
                        (event_id,)
                    )
                    network_events = cursor.fetchall()
                    if network_events:
                        event['network_details'] = [dict(row) for row in network_events]
                
                return events
            except Exception as e:
                logger.error(f"Error getting recent events: {e}")
                return []
            finally:
                conn.close()
    
    def get_config_value(self, key, default=None):
        """Get a configuration value from the database"""
        with self.lock:
            conn = self._get_connection()
            if not conn:
                return default
                
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT value FROM config 
                    WHERE key = ?
                    """, 
                    (key,)
                )
                row = cursor.fetchone()
                return row['value'] if row else default
            except Exception as e:
                logger.error(f"Error getting config value: {e}")
                return default
            finally:
                conn.close()
    
    def set_config_value(self, key, value):
        """Set a configuration value in the database"""
        with self.lock:
            conn = self._get_connection()
            if not conn:
                return False
                
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO config 
                    (key, value) 
                    VALUES (?, ?)
                    """, 
                    (key, value)
                )
                conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error setting config value: {e}")
                return False
            finally:
                conn.close()
