# WinSecDefender 🛡️

**WinSecDefender** is a security hardening and vulnerability scanner for Windows Server 2012+ environments. It performs network port scanning, system configuration audits (via PowerShell), and UAC policy checks (via C#).

## 🚀 Features

- **Port Scanning**: Identifies open ports (FTP, SMB, RDP).
- **System Hardening**: Checks for SMBv1, Unquoted Service Paths, and Patch status.
- **UAC Verification**: Ensures User Account Control is enabled via a custom C# binary.
- **Auto-Remediation**: Generates a PowerShell script to fix identified vulnerabilities.
- **Modern Dashboard**: Web-based interface built with FastAPI.

## 🛠️ Installation

1.  **Requirements**:

    - Python 3.8+
    - .NET Framework 4.5+ (for C# component)
    - PowerShell 5.1+

2.  **Setup**:

    ```bash
    pip install -r requirements.txt
    ```

3.  **Compile Components**:
    Run the build script to compile the C# helper:
    ```bash
    python build.py
    ```

## 🏃 Usage

1.  **Start the Server**:

    ```bash
    uvicorn app.main:app --reload
    ```

    Or simply run `python -m app.main` if configured.

2.  **Access Dashboard**:
    Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

3.  **Run Scan**:
    Click "Run Scan" to analyze the system. If vulnerabilities are found, click "Generate Fixes" to create a remediation script.

## 📂 Project Structure

- `app/`: Main Python application (FastAPI).
  - `api/`: API Routes and Logic.
  - `core/`: Scanner logic and configuration.
  - `templates/`: Web dashboard.
- `scripts/`: Helper scripts (`audit_script.ps1`, `RegistryInspector.cs`).
- `bin/`: Compiled executables.
- `reports/`: Scan output directories.

## ⚠️ Compatibility

- Designed for **Windows Server 2012 R2** and newer.
- Requires Administrator privileges for full auditing.
