
#!/usr/bin/env python3
# Anomaly Engine Module for RansomEye

import os
import time
import logging
import pickle
import numpy as np
from datetime import datetime
from collections import deque

logger = logging.getLogger("RansomEye.AnomalyEngine")

class AnomalyEngine:
    def __init__(self, db_writer, mitigation, confidence_threshold=0.7):
        self.db_writer = db_writer
        self.mitigation = mitigation
        self.confidence_threshold = confidence_threshold
        self.model = None
        
        # Feature history (for time-series analysis)
        self.file_history = deque(maxlen=100)
        self.process_history = deque(maxlen=100)
        self.network_history = deque(maxlen=100)
        
        # Load pre-trained model if available
        self.load_model()
    
    def load_model(self):
        """Load the pre-trained anomaly detection model"""
        model_path = os.path.join('ai', 'model.pkl')
        
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                logger.info(f"Loaded anomaly detection model from {model_path}")
            except Exception as e:
                logger.error(f"Error loading model: {e}")
                self.init_default_model()
        else:
            logger.warning(f"No pre-trained model found at {model_path}, initializing default model")
            self.init_default_model()
    
    def init_default_model(self):
        """Initialize a default model if no pre-trained model is available"""
        try:
            from sklearn.ensemble import IsolationForest
            
            # Create a default Isolation Forest model
            self.model = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42
            )
            logger.info("Initialized default anomaly detection model (Isolation Forest)")
            
            # Save the default model
            os.makedirs('ai', exist_ok=True)
            with open(os.path.join('ai', 'model.pkl'), 'wb') as f:
                pickle.dump(self.model, f)
                
        except ImportError:
            logger.error("sklearn not available, anomaly detection disabled")
            self.model = None
    
    def analyze_file(self, file_path, entropy, file_hash):
        """Analyze a file for anomalies"""
        try:
            # Extract features
            features = self._extract_file_features(file_path, entropy, file_hash)
            
            # Add to history for time-series analysis
            self.file_history.append(features)
            
            # If we don't have enough samples yet, return
            if len(self.file_history) < 5:
                return
            
            # Run anomaly detection if model is available
            if self.model:
                # Try to scale features for better detection
                try:
                    # Convert relevant features to numeric array
                    features_array = np.array([
                        features.get('entropy', 0),
                        features.get('is_executable', 0),
                        features.get('extension_risk', 0)
                    ]).reshape(1, -1)
                    
                    # Use a threshold of -0.5 to detect anomalies (adjust as needed)
                    # More negative means more anomalous
                    if hasattr(self.model, 'decision_function'):
                        score = self.model.decision_function(features_array)[0]
                    else:
                        # Fallback for models that don't have decision_function
                        score = -0.5
                        
                    # Convert score to confidence (0-1 range)
                    confidence = 1 - (score + 0.8) / 1.6  # Map range [-0.8, 0.8] to [1, 0]
                    confidence = max(0, min(confidence, 1))  # Clamp to [0, 1]
                    
                    if confidence > self.confidence_threshold:
                        self.report_anomaly(
                            'file', 
                            file_path,
                            confidence, 
                            features
                        )
                except Exception as e:
                    logger.error(f"Error in file anomaly detection: {e}")
                
        except Exception as e:
            logger.error(f"Error analyzing file: {e}")
    
    def analyze_process(self, pid, name, cmdline, process_tree):
        """Analyze a process for anomalies"""
        try:
            # Extract features
            features = self._extract_process_features(pid, name, cmdline, process_tree)
            
            # Add to history for time-series analysis
            self.process_history.append(features)
            
            # Manual detection based on features
            risk_score = features.get('risk_score', 0)
            if risk_score > 0.7:
                # High risk detected through rule-based analysis
                confidence = risk_score
                self.report_anomaly('process', name, confidence, features)
                
        except Exception as e:
            logger.error(f"Error analyzing process: {e}")
    
    def analyze_network(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """Analyze a network connection for anomalies"""
        try:
            # Extract features
            features = self._extract_network_features(src_ip, dst_ip, src_port, dst_port, protocol)
            
            # Add to history for time-series analysis
            self.network_history.append(features)
            
            # Manual detection based on features
            risk_score = features.get('risk_score', 0)
            if risk_score > 0.7:
                # High risk detected through rule-based analysis
                confidence = risk_score
                self.report_anomaly('network', f"{src_ip}:{src_port}->{dst_ip}:{dst_port}", 
                                  confidence, features)
                
        except Exception as e:
            logger.error(f"Error analyzing network connection: {e}")
    
    def report_anomaly(self, source_type, identifier, confidence, features):
        """Report an anomaly detection"""
        try:
            logger.warning(f"Anomaly detected: {source_type} - {identifier} (confidence: {confidence:.2f})")
            
            # Determine severity based on confidence
            severity = int(5 + confidence * 5)  # Scale 0-1 to severity 5-10
            
            # Format reason based on top features
            reason = f"Anomaly detected with {confidence:.2f} confidence"
            
            # Add event to database
            event_id = self.db_writer.add_event(
                event_type=f"anomaly_{source_type}",
                severity=severity,
                source="anomaly_engine",
                description=reason
            )
            
            # Take appropriate action based on source type
            if source_type == 'file':
                self.db_writer.add_file_event(
                    event_id=event_id,
                    file_path=identifier,
                    file_hash=features.get('file_hash', 'unknown'),
                    entropy=features.get('entropy', 0),
                    action_taken="anomaly_detected"
                )
                
                # Consider mitigation for high-confidence detections
                if confidence > 0.8:
                    self.mitigation.handle_file_threat(identifier, event_id)
                    
            elif source_type == 'process':
                self.db_writer.add_process_event(
                    event_id=event_id,
                    pid=features.get('pid', 0),
                    process_name=identifier,
                    command_line=features.get('cmdline', ''),
                    parent_pid=features.get('parent_pid', 0),
                    process_tree=features.get('process_tree', ''),
                    action_taken="anomaly_detected"
                )
                
                # Consider mitigation for high-confidence detections
                if confidence > 0.8:
                    self.mitigation.handle_process_threat(
                        features.get('pid', 0), 
                        identifier, 
                        features.get('cmdline', ''),
                        event_id
                    )
                    
            elif source_type == 'network':
                src_ip, dst_ip = identifier.split('->')[0].split(':')[0], identifier.split('->')[1].split(':')[0]
                src_port = int(identifier.split('->')[0].split(':')[1])
                dst_port = int(identifier.split('->')[1].split(':')[1])
                
                self.db_writer.add_network_event(
                    event_id=event_id,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol=features.get('protocol', 'unknown'),
                    packet_count=features.get('packet_count', 1),
                    action_taken="anomaly_detected"
                )
                
                # Consider mitigation for high-confidence detections
                if confidence > 0.8:
                    self.mitigation.handle_network_threat(
                        src_ip, dst_ip, src_port, dst_port, event_id
                    )
            
        except Exception as e:
            logger.error(f"Error reporting anomaly: {e}")
    
    def _extract_file_features(self, file_path, entropy, file_hash):
        """Extract features from a file for anomaly detection"""
        features = {
            'file_path': file_path,
            'file_hash': file_hash,
            'entropy': entropy,
            'timestamp': datetime.now().timestamp(),
            'extension_risk': 0,
            'is_executable': 0
        }
        
        # Check if file is executable
        if file_path.endswith(('.exe', '.sh', '.py', '.pl', '.rb')):
            features['is_executable'] = 1
        
        # Check extension risk
        suspicious_extensions = [
            '.exe', '.bat', '.ps1', '.vbs', '.js', '.hta', 
            '.encrypted', '.locked', '.crypted', '.cry', '.enc'
        ]
        
        if any(file_path.endswith(ext) for ext in suspicious_extensions):
            features['extension_risk'] = 0.8
        
        return features
    
    def _extract_process_features(self, pid, name, cmdline, process_tree):
        """Extract features from a process for anomaly detection"""
        features = {
            'pid': pid,
            'name': name,
            'cmdline': cmdline,
            'process_tree': process_tree,
            'timestamp': datetime.now().timestamp(),
            'risk_score': 0,
            'parent_pid': 0
        }
        
        # Calculate risk score based on process characteristics
        risk_score = 0
        
        # Check for suspicious commands
        suspicious_commands = [
            'wget', 'curl', 'nc ', 'netcat', 'base64',
            'chmod', 'chattr', 'dd if=/dev/urandom'
        ]
        
        for cmd in suspicious_commands:
            if cmd in cmdline:
                risk_score += 0.2
                
        # Check for suspicious command patterns
        if ('curl' in cmdline or 'wget' in cmdline) and ('sh' in cmdline or 'bash' in cmdline):
            risk_score += 0.3
            
        if 'chmod' in cmdline and 'execute' in cmdline:
            risk_score += 0.3
            
        # Check process ancestry
        if 'sshd' in process_tree and 'bash' in process_tree:
            risk_score += 0.1
            
        # Cap at 1.0
        features['risk_score'] = min(1.0, risk_score)
        
        return features
    
    def _extract_network_features(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """Extract features from a network connection for anomaly detection"""
        features = {
            'src_ip': src_ip,
            'dst_ip': dst_ip, 
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'timestamp': datetime.now().timestamp(),
            'risk_score': 0,
            'packet_count': 1
        }
        
        # Calculate risk score based on network characteristics
        risk_score = 0
        
        # Check for common C2 ports
        suspicious_ports = [4444, 4445, 1234, 6666, 6667, 6668, 6669, 8080, 
                           9001, 9050, 8333, 31337, 12345, 54321]
        
        if src_port in suspicious_ports or dst_port in suspicious_ports:
            risk_score += 0.3
            
        # Check for suspicious destinations
        suspicious_ip_patterns = [
            "192.42.116.", "195.123.246.", "185.130.44.",
            "94.142.138.", "94.23.", "31.184."
        ]
        
        for pattern in suspicious_ip_patterns:
            if dst_ip.startswith(pattern):
                risk_score += 0.4
                break
                
        # Check for TOR exit node ports
        if dst_port in [9050, 9051]:
            risk_score += 0.5
            
        # Cap at 1.0
        features['risk_score'] = min(1.0, risk_score)
        
        return features
