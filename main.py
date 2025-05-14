
#!/usr/bin/env python3
# RansomEye - Main Entry Point

import argparse
import os
import sys
import sqlite3
import multiprocessing
import logging
from datetime import datetime

# Import core modules
from core.filesystem_scanner import FilesystemScanner
from core.process_monitor import ProcessMonitor
from core.network_sniffer import NetworkSniffer
from core.anomaly_engine import AnomalyEngine
from core.mitigation import Mitigation

# Import UI
from ui.dashboard import start_dashboard

# Import utilities
from utils.db_writer import DatabaseWriter

def setup_logging():
    """Configure logging for the application"""
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    log_file = os.path.join(log_dir, f"ransomeye_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger("RansomEye")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='RansomEye - Ransomware Detection Platform')
    parser.add_argument('--no-gui', action='store_true', help='Run in CLI mode without GUI')
    parser.add_argument('--scan', choices=['quick', 'full'], default='quick', 
                       help='Scan mode: quick or full')
    parser.add_argument('--config', type=str, help='Path to configuration file')
    return parser.parse_args()

def load_config(db_path, args):
    """Load configuration from database or file"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM config")
    config = dict(cursor.fetchall())
    conn.close()
    
    # If config file specified, override database settings
    if args.config and os.path.exists(args.config):
        import json
        with open(args.config, 'r') as f:
            file_config = json.load(f)
            config.update(file_config)
    
    return config

def start_modules(queue, config, logger):
    """Start all monitoring modules in separate processes"""
    processes = []
    
    # Create shared database writer
    db_writer = DatabaseWriter('data/ransomeye.db')
    
    # Initialize mitigation engine
    mitigation = Mitigation(db_writer, auto_mitigate=config.get('auto_mitigation') == 'True')
    
    # Initialize the anomaly engine
    anomaly_engine = AnomalyEngine(db_writer, mitigation, 
                                   confidence_threshold=float(config.get('ai_confidence_threshold')))
    
    # Start Filesystem Scanner
    fs_scanner = FilesystemScanner(db_writer, anomaly_engine, mitigation,
                                  entropy_threshold=float(config.get('entropy_threshold')),
                                  scan_interval=int(config.get('scan_interval')))
    
    fs_process = multiprocessing.Process(target=fs_scanner.start_monitoring)
    fs_process.daemon = True
    fs_process.start()
    processes.append(fs_process)
    logger.info("Filesystem Scanner started")
    
    # Start Process Monitor
    process_monitor = ProcessMonitor(db_writer, anomaly_engine, mitigation,
                                    cpu_threshold=int(config.get('process_cpu_threshold')))
    
    pm_process = multiprocessing.Process(target=process_monitor.start_monitoring)
    pm_process.daemon = True
    pm_process.start()
    processes.append(pm_process)
    logger.info("Process Monitor started")
    
    # Start Network Sniffer
    network_sniffer = NetworkSniffer(db_writer, anomaly_engine, mitigation,
                                    conn_threshold=int(config.get('network_conn_threshold')))
    
    ns_process = multiprocessing.Process(target=network_sniffer.start_monitoring)
    ns_process.daemon = True
    ns_process.start()
    processes.append(ns_process)
    logger.info("Network Sniffer started")
    
    return processes

def main():
    """Main entry point for RansomEye"""
    # Setup logging
    logger = setup_logging()
    logger.info("Starting RansomEye...")
    
    # Parse arguments
    args = parse_arguments()
    
    # Create required directories if they don't exist
    os.makedirs("data", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    
    # Load configuration
    config = load_config('data/ransomeye.db', args)
    logger.info(f"Configuration loaded: {config}")
    
    # Create a message queue for communication between modules
    message_queue = multiprocessing.Queue()
    
    # Start the monitoring modules
    processes = start_modules(message_queue, config, logger)
    
    try:
        if not args.no_gui:
            # Start the dashboard (blocking call)
            logger.info("Starting dashboard...")
            start_dashboard(message_queue, config)
        else:
            # If no GUI, wait for processes to finish (which they won't, as they're daemon processes)
            logger.info("Running in CLI mode")
            for p in processes:
                p.join()
    except KeyboardInterrupt:
        logger.info("Shutdown requested...")
    except Exception as e:
        logger.error(f"Error in main loop: {e}")
    finally:
        # Clean shutdown
        logger.info("Shutting down RansomEye...")
        message_queue.close()
        for p in processes:
            if p.is_alive():
                p.terminate()
        
        logger.info("RansomEye shutdown complete")

if __name__ == "__main__":
    multiprocessing.set_start_method('spawn')
    main()
