
#!/bin/bash

echo "===== RansomEye Installer ====="
echo "Installing required packages..."

# Update repositories
sudo apt update

# Install Python and required system dependencies
sudo apt install -y python3 python3-pip python3-dev python3-tk libpcap-dev \
  build-essential sqlite3 suricata zeek tcpdump curl git

# Create directory structure
mkdir -p core ai ui utils data reports logs

# Install Python dependencies
pip3 install psutil watchdog scapy PyPDF2 pyqt5 sklearn numpy pandas matplotlib \
  scikit-learn joblib tqdm pdfkit tabulate

echo "Setting up the SQLite database..."
sqlite3 data/ransomeye.db < db_setup.sql

echo "Setting appropriate permissions..."
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

echo "Installation complete!"
echo "Run 'python3 main.py' to start RansomEye"
