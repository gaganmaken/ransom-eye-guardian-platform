
#!/usr/bin/env python3
# RansomEye - Windows Build Script

import os
import shutil
import subprocess
import sys
import site
import glob

def check_requirements():
    """Check and install required packages"""
    required_packages = [
        'PyInstaller',
        'psutil',
        'watchdog',
        'scapy',
        'PyPDF2',
        'scikit-learn',
        'numpy',
        'pandas',
        'matplotlib',
        'joblib',
        'tqdm',
        'pdfkit',
        'tabulate'
    ]
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"{package} is already installed.")
        except ImportError:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def collect_dependencies():
    """Collect all necessary dependencies for the application"""
    # Get site-packages directory
    site_packages = site.getsitepackages()[0]
    print(f"Site packages directory: {site_packages}")
    
    # Create temp directory for dependencies
    if not os.path.exists("temp_deps"):
        os.makedirs("temp_deps")
    
    # Copy necessary dependencies to temp directory
    dependencies = [
        "core", "ai", "ui", "utils", "data"
    ]
    
    for dep in dependencies:
        if os.path.exists(dep):
            if os.path.isdir(dep):
                if os.path.exists(f"temp_deps/{dep}"):
                    shutil.rmtree(f"temp_deps/{dep}")
                shutil.copytree(dep, f"temp_deps/{dep}")
            else:
                shutil.copy(dep, "temp_deps/")
            print(f"Collected dependency: {dep}")
    
    # Create necessary empty directories
    for dir_name in ["logs", "reports"]:
        os.makedirs(f"temp_deps/{dir_name}", exist_ok=True)
    
    return True

def build_executable():
    """Build the Windows executable using PyInstaller"""
    print("Building RansomEye Windows executable...")
    
    # Create build directory if it doesn't exist
    if not os.path.exists("build"):
        os.makedirs("build")
    
    # Clean previous build artifacts if they exist
    if os.path.exists("dist"):
        shutil.rmtree("dist")
    if os.path.exists("build/ransomeye"):
        shutil.rmtree("build/ransomeye")
    
    # Collect all necessary files
    collect_dependencies()
    
    # Define additional data files to include
    additional_data = [
        ("temp_deps/core", "core"),
        ("temp_deps/ai", "ai"),
        ("temp_deps/ui", "ui"),
        ("temp_deps/utils", "utils"),
        ("temp_deps/data", "data"),
        ("temp_deps/logs", "logs"),
        ("temp_deps/reports", "reports"),
        ("public/favicon.ico", "."),
    ]
    
    # Prepare data arguments for PyInstaller
    data_args = []
    for src, dest in additional_data:
        if os.path.exists(src):
            data_args.extend(["--add-data", f"{src};{dest}"])
    
    # Build the executable
    pyinstaller_args = [
        "pyinstaller",
        "--name=RansomEye",
        "--icon=public/favicon.ico",
        "--noconsole",  # No console window
        "--onefile",    # Single executable file
        "--clean",      # Clean PyInstaller cache
        "--log-level=INFO",
    ]
    
    # Add all data arguments
    pyinstaller_args.extend(data_args)
    
    # Add the main script
    pyinstaller_args.append("main.py")
    
    # Execute PyInstaller
    print("Executing PyInstaller with arguments:", " ".join(pyinstaller_args))
    subprocess.check_call(pyinstaller_args)
    
    print("Creating Windows installer...")
    try:
        import InnoSetup
        print("InnoSetup module is already installed.")
    except ImportError:
        print("Note: For a full installer, install InnoSetup manually and run:")
        print("iscc setup_script.iss")
    
    # Create InnoSetup script
    with open("setup_script.iss", "w") as f:
        f.write("""
#define MyAppName "RansomEye"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "RansomEye Security"
#define MyAppURL "https://www.ransomeye.security/"
#define MyAppExeName "RansomEye.exe"

[Setup]
AppId={{BA128A55-C3F4-4A0B-9FA1-5EF8150D397C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=LICENSE
OutputDir=installer
OutputBaseFilename=RansomEye_Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}";
Name: "startupicon"; Description: "Start at system startup"; GroupDescription: "{cm:AdditionalIcons}";

[Files]
Source: "dist\\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"
Name: "{autodesktop}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"; Tasks: desktopicon
Name: "{commonstartup}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"; Tasks: startupicon

[Run]
Filename: "{app}\\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
""")
    
    # Clean up temporary files
    if os.path.exists("temp_deps"):
        shutil.rmtree("temp_deps")
    
    print("Build completed!")
    print("Executable created at: dist/RansomEye.exe")
    print("To create an installer, install InnoSetup and run: iscc setup_script.iss")

if __name__ == "__main__":
    print("==== RansomEye Windows Build Script ====")
    check_requirements()
    build_executable()
