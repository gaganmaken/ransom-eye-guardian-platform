
# RansomEye: Modular Ransomware Detection Platform

RansomEye is a comprehensive, offline-capable ransomware detection, evidence collection, and response platform designed for Linux systems. This platform employs multiple monitoring strategies and AI/ML-based anomaly detection to identify and mitigate ransomware threats in real-time.

## Features

- **Completely offline operation** - Works in air-gapped environments
- **Real-time monitoring** of file systems, processes, and network activity
- **AI-powered anomaly detection** using Isolation Forest algorithm
- **Automatic threat mitigation** capabilities
- **Comprehensive dashboard** for threat visualization and analysis
- **Evidence collection** and detailed reporting
- **Modular architecture** for easy expansion and customization

## System Requirements

- **Operating System**: Ubuntu 22.04 or later
- **Minimum Hardware**:
  - 4 CPU cores
  - 16 GB RAM
  - 50 GB SSD storage
- **Python**: Version 3.8 or later

## Installation

### Option 1: Automated Installation

1. Clone this repository or download it to your target system
2. Make the installer script executable:
   ```
   chmod +x install.sh
   ```
3. Run the installer:
   ```
   ./install.sh
   ```

### Option 2: Manual Installation

1. Install required system dependencies:
   ```
   sudo apt update
   sudo apt install -y python3 python3-pip python3-dev python3-tk libpcap-dev build-essential sqlite3 suricata zeek tcpdump curl git
   ```

2. Install Python dependencies:
   ```
   pip3 install psutil watchdog scapy PyPDF2 pyqt5 sklearn numpy pandas matplotlib scikit-learn joblib tqdm pdfkit tabulate
   ```

3. Set up the SQLite database:
   ```
   sqlite3 data/ransomeye.db < db_setup.sql
   ```

4. Set appropriate permissions for network capture:
   ```
   sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
   ```

## Usage

### Starting RansomEye

Run the main application:
```
python3 main.py
```

For CLI mode (no GUI):
```
python3 main.py --no-gui
```

For different scan modes:
```
python3 main.py --scan quick
python3 main.py --scan full
```

### Using the Dashboard

The dashboard provides a comprehensive view of your system's security status:

1. **Dashboard Tab**: Overview of alerts, system status, and statistics
2. **Events Tab**: All security events with filtering options
3. **Files Tab**: Suspicious file detections and quarantine management
4. **Processes Tab**: Suspicious process detections with termination options
5. **Network Tab**: Suspicious network connections with blocking capabilities
6. **Reports Tab**: Generate and manage security reports
7. **Configuration Tab**: Configure detection thresholds and monitoring behavior

### Emergency Controls

In case of detected threats, the dashboard provides emergency controls:

- **Isolate System**: Disconnect the system from the network
- **Kill Suspicious Processes**: Terminate all flagged suspicious processes
- **Generate Incident Report**: Create comprehensive incident documentation

## AI Model Training

RansomEye includes an AI model for anomaly detection. You can train it with your own data:

```
python3 ai/train_model.py
```

The model will be trained using historical data from the RansomEye database. If insufficient data is available, the script will generate synthetic data for initial training.

## Detection Capabilities

RansomEye is designed to detect:

- **File encryption patterns** through entropy analysis
- **Suspicious file extensions** and file operations
- **Malicious process execution chains**
- **Command and control (C2) communications**
- **Known attack patterns** for common ransomware families
- **Lateral movement attempts** within a network
- **Deletion of backup files** or critical system components

## Configuration

The system is highly configurable through the GUI or by directly modifying the database config table:

- **Scan interval**: Frequency of full system scans
- **Entropy threshold**: Sensitivity for detecting encrypted files
- **Process CPU threshold**: CPU usage threshold for suspicious processes
- **Network connection threshold**: Connection rate threshold for network analysis
- **AI confidence threshold**: Minimum confidence for AI-based detections
- **Auto-mitigation**: Enable/disable automatic threat response

## Troubleshooting

### Permissions Issues

If experiencing permission issues with network capture:

```
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

### Database Errors

If the database becomes corrupted, you can reset it:

```
rm data/ransomeye.db
sqlite3 data/ransomeye.db < db_setup.sql
```

### Python Dependency Issues

If encountering dependency issues:

```
pip3 install --upgrade -r requirements.txt
```

## Project Structure

```
RansomEye/
├── core/                # Core monitoring modules
│   ├── filesystem_scanner.py
│   ├── process_monitor.py
│   ├── network_sniffer.py
│   ├── anomaly_engine.py
│   └── mitigation.py
├── ai/                  # AI model training and inference
│   ├── train_model.py
│   ├── ai_model.py
│   └── model.pkl
├── ui/                  # User interface components
│   └── dashboard.py
├── utils/               # Utility functions
│   ├── entropy_calc.py
│   ├── file_hashing.py
│   └── db_writer.py
├── data/                # Data storage
│   └── ransomeye.db
├── reports/             # Generated reports
├── logs/                # System logs
├── install.sh           # Installation script
├── main.py              # Main entry point
└── README.md            # Documentation
```

## Security Considerations

RansomEye requires elevated privileges to monitor system processes and network traffic. Please ensure:

1. The system running RansomEye is secured and hardened
2. Access to the RansomEye dashboard is restricted to authorized personnel
3. Auto-mitigation features are carefully tested in your environment before enabling

## License

[MIT License](LICENSE)

## Contributors

- RansomEye Development Team

## Acknowledgements

This project utilizes several open-source libraries and tools, including:
- scikit-learn for machine learning capabilities
- Scapy for network traffic analysis
- Tkinter for the graphical user interface
- SQLite for data storage
