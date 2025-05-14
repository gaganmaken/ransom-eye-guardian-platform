
#!/usr/bin/env python3
# AI Model Training for RansomEye

import os
import sys
import sqlite3
import pickle
import numpy as np
import logging
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"logs/ai_training_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("RansomEye.AI.Training")

def create_synthetic_dataset():
    """Create synthetic dataset for model training if no real data is available"""
    logger.info("Creating synthetic dataset for model training...")
    
    # Synthetic data for files
    file_data = []
    
    # Normal files (low entropy, normal extensions)
    for i in range(500):
        entropy = np.random.uniform(2.5, 6.5)  # Normal entropy range
        extension_risk = np.random.uniform(0, 0.2)  # Low risk extensions
        is_executable = np.random.choice([0, 1], p=[0.9, 0.1])  # Mostly non-executable
        file_data.append([entropy, extension_risk, is_executable])
    
    # Suspicious files (high entropy, suspicious extensions)
    for i in range(50):
        entropy = np.random.uniform(7.5, 8.0)  # High entropy range
        extension_risk = np.random.uniform(0.7, 1.0)  # High risk extensions
        is_executable = np.random.choice([0, 1], p=[0.3, 0.7])  # More likely executable
        file_data.append([entropy, extension_risk, is_executable])
    
    # Synthetic data for processes
    process_data = []
    
    # Normal processes
    for i in range(500):
        cpu_usage = np.random.uniform(0, 50)  # Low to moderate CPU usage
        suspicious_cmd_score = np.random.uniform(0, 0.3)  # Low suspicion score
        ancestry_depth = np.random.randint(1, 4)  # Shallow process tree
        process_data.append([cpu_usage, suspicious_cmd_score, ancestry_depth])
    
    # Suspicious processes
    for i in range(50):
        cpu_usage = np.random.uniform(70, 100)  # High CPU usage
        suspicious_cmd_score = np.random.uniform(0.6, 1.0)  # High suspicion score
        ancestry_depth = np.random.randint(3, 7)  # Deep process tree
        process_data.append([cpu_usage, suspicious_cmd_score, ancestry_depth])
    
    # Synthetic data for network
    network_data = []
    
    # Normal network connections
    for i in range(500):
        connection_rate = np.random.uniform(1, 20)  # Low connection rate
        port_risk = np.random.uniform(0, 0.3)  # Common ports
        outbound = np.random.choice([0, 1], p=[0.3, 0.7])  # Mostly outbound
        network_data.append([connection_rate, port_risk, outbound])
    
    # Suspicious network connections
    for i in range(50):
        connection_rate = np.random.uniform(40, 100)  # High connection rate
        port_risk = np.random.uniform(0.7, 1.0)  # Suspicious ports
        outbound = np.random.choice([0, 1], p=[0.1, 0.9])  # Almost all outbound
        network_data.append([connection_rate, port_risk, outbound])
    
    # Convert to numpy arrays
    file_data = np.array(file_data)
    process_data = np.array(process_data)
    network_data = np.array(network_data)
    
    return {
        "file_data": file_data,
        "process_data": process_data,
        "network_data": network_data
    }

def extract_data_from_database(db_path):
    """Extract real data from the database for model training"""
    logger.info(f"Extracting data from database: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Extract file data
        cursor.execute("""
            SELECT entropy, file_path
            FROM file_events
        """)
        file_results = cursor.fetchall()
        
        # Extract process data
        cursor.execute("""
            SELECT process_name, command_line, process_tree
            FROM process_events
        """)
        process_results = cursor.fetchall()
        
        # Extract network data
        cursor.execute("""
            SELECT source_port, destination_port, protocol
            FROM network_events
        """)
        network_results = cursor.fetchall()
        
        conn.close()
        
        # Process file data
        file_data = []
        for entropy, file_path in file_results:
            # Calculate extension risk
            extension_risk = 0.0
            if file_path:
                extension = os.path.splitext(file_path)[-1].lower()
                suspicious_extensions = ['.exe', '.bat', '.ps1', '.vbs', '.js', '.hta', 
                                        '.encrypted', '.locked', '.crypted', '.cry', '.enc']
                extension_risk = 1.0 if extension in suspicious_extensions else 0.0
            
            # Determine if executable
            is_executable = 1 if file_path and file_path.endswith(('.exe', '.sh', '.py', '.pl', '.rb')) else 0
            
            file_data.append([entropy, extension_risk, is_executable])
        
        # Process process data
        process_data = []
        for name, cmdline, tree in process_results:
            # Calculate suspicion score based on command
            suspicion_score = 0.0
            suspicious_terms = ['wget', 'curl', 'base64', 'chmod', 'rm -rf']
            for term in suspicious_terms:
                if cmdline and term in cmdline:
                    suspicion_score += 0.2
            
            # Calculate ancestry depth
            ancestry_depth = 1
            if tree:
                ancestry_depth = tree.count("->") + 1
            
            process_data.append([0.0, min(suspicion_score, 1.0), ancestry_depth])  # We don't have CPU usage in the DB
        
        # Process network data
        network_data = []
        for src_port, dst_port, protocol in network_results:
            # Calculate port risk
            port_risk = 0.0
            suspicious_ports = [4444, 4445, 1234, 6666, 6667, 6668, 6669, 8080, 
                              9001, 9050, 8333, 31337, 12345, 54321]
            if src_port in suspicious_ports or dst_port in suspicious_ports:
                port_risk = 1.0
            
            network_data.append([0.0, port_risk, 1.0])  # We don't have connection rate in the DB
        
        # Convert to numpy arrays
        file_data = np.array(file_data) if file_data else np.empty((0, 3))
        process_data = np.array(process_data) if process_data else np.empty((0, 3))
        network_data = np.array(network_data) if network_data else np.empty((0, 3))
        
        return {
            "file_data": file_data,
            "process_data": process_data,
            "network_data": network_data
        }
        
    except Exception as e:
        logger.error(f"Error extracting data from database: {e}")
        return None

def train_file_model(file_data):
    """Train anomaly detection model for files"""
    logger.info(f"Training file anomaly detection model with {len(file_data)} samples")
    
    if len(file_data) < 10:
        logger.warning("Not enough file samples for training, using default model")
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        return model
    
    # Normalize the data
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(file_data)
    
    # Train Isolation Forest model
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,  # Assuming 10% of the data might be anomalous
        random_state=42
    )
    
    model.fit(scaled_data)
    logger.info("File model training complete")
    
    return model

def train_process_model(process_data):
    """Train anomaly detection model for processes"""
    logger.info(f"Training process anomaly detection model with {len(process_data)} samples")
    
    if len(process_data) < 10:
        logger.warning("Not enough process samples for training, using default model")
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        return model
    
    # Normalize the data
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(process_data)
    
    # Train Isolation Forest model
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42
    )
    
    model.fit(scaled_data)
    logger.info("Process model training complete")
    
    return model

def train_network_model(network_data):
    """Train anomaly detection model for network connections"""
    logger.info(f"Training network anomaly detection model with {len(network_data)} samples")
    
    if len(network_data) < 10:
        logger.warning("Not enough network samples for training, using default model")
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        return model
    
    # Normalize the data
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(network_data)
    
    # Train Isolation Forest model
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42
    )
    
    model.fit(scaled_data)
    logger.info("Network model training complete")
    
    return model

def save_model(model, filename):
    """Save model to disk"""
    try:
        with open(filename, 'wb') as f:
            pickle.dump(model, f)
        logger.info(f"Model saved to {filename}")
        return True
    except Exception as e:
        logger.error(f"Error saving model to {filename}: {e}")
        return False

def main():
    """Main training function"""
    logger.info("Starting AI model training")
    
    # Create ai directory if it doesn't exist
    os.makedirs("ai", exist_ok=True)
    
    # Attempt to extract data from database
    db_data = extract_data_from_database('data/ransomeye.db')
    
    # If no database data, use synthetic data
    if not db_data or all(len(v) == 0 for v in db_data.values()):
        logger.info("No real data found, using synthetic dataset")
        data = create_synthetic_dataset()
    else:
        logger.info("Using real data from database")
        data = db_data
    
    # Train models
    file_model = train_file_model(data["file_data"])
    process_model = train_process_model(data["process_data"])
    network_model = train_network_model(data["network_data"])
    
    # Save models
    save_model(file_model, "ai/file_model.pkl")
    save_model(process_model, "ai/process_model.pkl")
    save_model(network_model, "ai/network_model.pkl")
    
    # Save a combined model for backward compatibility
    combined_model = {
        "file_model": file_model,
        "process_model": process_model,
        "network_model": network_model
    }
    save_model(combined_model, "ai/model.pkl")
    
    logger.info("Model training complete")

if __name__ == "__main__":
    main()
