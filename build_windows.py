
#!/usr/bin/env python3
# RansomEye - Windows Build Script

import os
import shutil
import subprocess
import sys

def check_requirements():
    """Check if required packages are installed"""
    try:
        import PyInstaller
        print("PyInstaller is already installed.")
    except ImportError:
        print("Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

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
    
    # Build the executable
    subprocess.check_call([
        "pyinstaller",
        "--name=RansomEye",
        "--icon=public/favicon.ico",
        "--noconsole",  # No console window
        "--onefile",    # Single executable file
        "--add-data=data;data",  # Include data directory
        "--add-data=ui;ui",      # Include UI directory
        "--add-data=core;core",  # Include core directory
        "--add-data=ai;ai",      # Include AI directory
        "--add-data=utils;utils",  # Include utils directory
        "main.py"
    ])
    
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
Source: "logs\\*"; DestDir: "{app}\\logs"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "dist\\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"
Name: "{autodesktop}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"; Tasks: desktopicon
Name: "{commonstartup}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"; Tasks: startupicon

[Run]
Filename: "{app}\\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
""")
    
    print("Build completed!")
    print("Executable created at: dist/RansomEye.exe")
    print("To create an installer, install InnoSetup and run: iscc setup_script.iss")

if __name__ == "__main__":
    print("==== RansomEye Windows Build Script ====")
    check_requirements()
    build_executable()

