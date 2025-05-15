
# RansomEye Windows Installation Guide

## Building the Windows Executable

### Prerequisites:
- Python 3.7 or higher
- Git (optional, for cloning the repository)

### Quick Installation:

1. Run the build script by double-clicking `build_windows.bat`
   - This will automatically install PyInstaller and other required packages if needed
   - The script will create a single executable file at `dist/RansomEye.exe`

### Manual Installation Steps:

1. Install the required Python packages:
   ```
   pip install pyinstaller psutil watchdog scapy PyPDF2 scikit-learn numpy pandas matplotlib joblib tqdm pdfkit tabulate
   ```

2. Run the build script:
   ```
   python build_windows.py
   ```

3. Find the executable in the `dist` directory

### Creating an Installer (Optional):

To create a Windows installer:

1. Download and install InnoSetup from https://jrsoftware.org/isinfo.php
2. Run InnoSetup and open the `setup_script.iss` file
3. Click "Compile" to create the installer
4. The installer will be created in the `installer` directory

## Running RansomEye:

After building:
1. Run `RansomEye.exe` directly from the `dist` directory
2. Or install using the installer (if created) and run from the Start Menu

## Features Included in the Executable:

- Complete ransomware detection engine
- Filesystem monitoring
- Process activity monitoring
- Network traffic analysis
- AI-powered anomaly detection
- Threat remediation tools
- Full dashboard interface

## Common Issues:

### Antivirus Detection
Some antivirus software may flag the executable. This is a false positive due to the nature of the application's scanning capabilities. Add an exception in your antivirus software if necessary.

### Network Capturing Issues
For network capturing functionalities, you may need to run the application as Administrator.

### Missing DLL Errors
If you encounter any missing DLL errors, ensure you have the latest Visual C++ Redistributable installed on your system.

## Support:

For additional support, please contact support@ransomeye.security.
