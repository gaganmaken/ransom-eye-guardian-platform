
#!/usr/bin/env python3
# AI Model Inference for RansomEye

import os
import pickle
import logging
import numpy as np
from datetime import datetime

logger = logging.getLogger("RansomEye.AI.Model")

class AIModel:
    def __init__(self):
        """Initialize the AI models"""
        self.file_model = None
        self.process_model = None
        self.network_model = None
        
        # Load models
        self.load_models()
    
    def load_models(self):
        """Load pre-trained models"""
        try:
            # Check if we have individual models
            if os.path.exists('ai/file_model.pkl'):
                with open('ai/file_model.pkl', 'rb') as f:
                    self.file_model = pickle.load(f)
                logger.info("Loaded file anomaly detection model")
            
            if os.path.exists('ai/process_model.pkl'):
                with open('ai/process_model.pkl', 'rb') as f:
                    self.process_model = pickle.load(f)
                logger.info("Loaded process anomaly detection model")
            
            if os.path.exists('ai/network_model.pkl'):
                with open('ai/network_model.pkl', 'rb') as f:
                    self.network_model = pickle.load(f)
                logger.info("Loaded network anomaly detection model")
            
            # Fallback to combined model if individual models don't exist
            if not all([self.file_model, self.process_model, self.network_model]):
                combined_model_path = 'ai/model.pkl'
                if os.path.exists(combined_model_path):
                    with open(combined_model_path, 'rb') as f:
                        combined_model = pickle.load(f)
                    
                    if isinstance(combined_model, dict):
                        self.file_model = combined_model.get('file_model')
                        self.process_model = combined_model.get('process_model')
                        self.network_model = combined_model.get('network_model')
                    else:
                        # If not a dict, assume it's a single model we'll use for everything
                        self.file_model = combined_model
                        self.process_model = combined_model
                        self.network_model = combined_model
                    
                    logger.info("Loaded combined anomaly detection model")
            
            # If we still don't have models, initialize defaults
            if not self.file_model:
                from sklearn.ensemble import IsolationForest
                self.file_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
                logger.warning("Using default file anomaly model")
            
            if not self.process_model:
                from sklearn.ensemble import IsolationForest
                self.process_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
                logger.warning("Using default process anomaly model")
            
            if not self.network_model:
                from sklearn.ensemble import IsolationForest
                self.network_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
                logger.warning("Using default network anomaly model")
                
        except Exception as e:
            logger.error(f"Error loading AI models: {e}")
            # Initialize default models if loading fails
            from sklearn.ensemble import IsolationForest
            self.file_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
            self.process_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
            self.network_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
            logger.warning("Using default anomaly models due to loading error")
    
    def predict_file_anomaly(self, entropy, extension_risk, is_executable):
        """Predict if a file is anomalous based on its features"""
        try:
            if not self.file_model:
                logger.warning("File model not available, skipping prediction")
                return 0.5  # Middle confidence when no model
            
            # Create feature vector
            features = np.array([[entropy, extension_risk, is_executable]])
            
            # Get anomaly score
            if hasattr(self.file_model, 'decision_function'):
                score = self.file_model.decision_function(features)[0]
                
                # Convert score to confidence (0-1 range)
                # More negative score means more anomalous
                confidence = 1 - (score + 0.8) / 1.6  # Map range [-0.8, 0.8] to [1, 0]
                confidence = max(0, min(confidence, 1))  # Clamp to [0, 1]
                
                return confidence
            else:
                # Fallback if model doesn't have decision_function
                prediction = self.file_model.predict(features)[0]
                return 0.8 if prediction == -1 else 0.2
                
        except Exception as e:
            logger.error(f"Error predicting file anomaly: {e}")
            return 0.5  # Default to middle confidence on error
    
    def predict_process_anomaly(self, cpu_usage, cmd_score, ancestry_depth):
        """Predict if a process is anomalous based on its features"""
        try:
            if not self.process_model:
                logger.warning("Process model not available, skipping prediction")
                return 0.5  # Middle confidence when no model
            
            # Create feature vector
            features = np.array([[cpu_usage, cmd_score, ancestry_depth]])
            
            # Get anomaly score
            if hasattr(self.process_model, 'decision_function'):
                score = self.process_model.decision_function(features)[0]
                
                # Convert score to confidence (0-1 range)
                confidence = 1 - (score + 0.8) / 1.6  # Map range [-0.8, 0.8] to [1, 0]
                confidence = max(0, min(confidence, 1))  # Clamp to [0, 1]
                
                return confidence
            else:
                # Fallback if model doesn't have decision_function
                prediction = self.process_model.predict(features)[0]
                return 0.8 if prediction == -1 else 0.2
                
        except Exception as e:
            logger.error(f"Error predicting process anomaly: {e}")
            return 0.5  # Default to middle confidence on error
    
    def predict_network_anomaly(self, conn_rate, port_risk, outbound):
        """Predict if network activity is anomalous based on its features"""
        try:
            if not self.network_model:
                logger.warning("Network model not available, skipping prediction")
                return 0.5  # Middle confidence when no model
            
            # Create feature vector
            features = np.array([[conn_rate, port_risk, outbound]])
            
            # Get anomaly score
            if hasattr(self.network_model, 'decision_function'):
                score = self.network_model.decision_function(features)[0]
                
                # Convert score to confidence (0-1 range)
                confidence = 1 - (score + 0.8) / 1.6  # Map range [-0.8, 0.8] to [1, 0]
                confidence = max(0, min(confidence, 1))  # Clamp to [0, 1]
                
                return confidence
            else:
                # Fallback if model doesn't have decision_function
                prediction = self.network_model.predict(features)[0]
                return 0.8 if prediction == -1 else 0.2
                
        except Exception as e:
            logger.error(f"Error predicting network anomaly: {e}")
            return 0.5  # Default to middle confidence on error

# Global instance for convenience
ai_model = AIModel()
