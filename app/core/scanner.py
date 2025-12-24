import asyncio
import socket
import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Any
from app.core.config import settings

logger = logging.getLogger(__name__)

class HybridScanner:
    def __init__(self, target_ip: str = settings.TARGET_IP):
        self.target_ip = target_ip
        self.report_data: Dict[str, Any] = {}
        self.fixes: List[Dict[str, str]] = []
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    async def scan_network_ports(self) -> List[Dict[str, Any]]:
        """Async port scanning"""
        logger.info(f"Scanning ports on {self.target_ip}...")
        common_ports = {
            21: "FTP (File Transfer)",
            445: "SMB (Windows File Sharing)",
            3389: "RDP (Remote Desktop)"
        }
        open_ports = []
        
        async def check_port(port, desc):
            try:
                 future = asyncio.open_connection(self.target_ip, port)
                 reader, writer = await asyncio.wait_for(future, timeout=0.5)
                 writer.close()
                 await writer.wait_closed()
                 return {"port": port, "service": desc, "status": "OPEN"}
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

        tasks = [check_port(port, desc) for port, desc in common_ports.items()]
        results = await asyncio.gather(*tasks)
        
        open_ports = [r for r in results if r is not None]
        self.report_data["Network_Scan"] = open_ports
        return open_ports

    async def run_powershell_module(self) -> Dict[str, Any]:
        """Executes PS1 script asynchronously"""
        ps_script_path = os.path.join(settings.SCRIPTS_DIR, "audit_script.ps1")
        logger.info(f"Running PowerShell: {ps_script_path}")
        
        if not os.path.exists(ps_script_path):
            logger.error(f"Script not found: {ps_script_path}")
            return {"error": "Script not found"}

        try:
            # -ExecutionPolicy Bypass is required
            process = await asyncio.create_subprocess_exec(
                "powershell", "-ExecutionPolicy", "Bypass", "-File", ps_script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if stdout:
                try:
                    ps_data = json.loads(stdout.decode().strip())
                    self.report_data["System_Config"] = ps_data
                    self._analyze_ps_results(ps_data)
                    return ps_data
                except json.JSONDecodeError:
                    logger.error("Failed to decode PowerShell JSON output")
                    return {"error": "Invalid JSON output", "raw": stdout.decode()}
            else:
                 logger.error(f"PowerShell Error: {stderr.decode()}")
                 return {"error": stderr.decode()}

        except Exception as e:
            logger.error(f"PowerShell execution failed: {str(e)}")
            return {"error": str(e)}

    def _analyze_ps_results(self, ps_data: Dict[str, Any]):
        """Analyze results and generate fixes"""
        if ps_data.get("SMBv1_Status") == "Enabled":
            self.fixes.append({
                "desc": "Disable SMBv1 (WannaCry Risk)",
                "cmd": "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
            })

        if ps_data.get("Unquoted_Services", "None") != "None":
            # Improved robust fix script
            fix_code = r'''
$services = Get-WmiObject win32_service | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -notmatch '^"' -and $_.PathName -match '\s' }
foreach ($service in $services) {
    if ($service.PathName -notmatch '^\"') {
        $newPath = '"' + $service.PathName + '"'
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)" -Name "ImagePath" -Value $newPath
    }
}'''
            self.fixes.append({"desc": "Fix Unquoted Service Paths", "cmd": fix_code})

    async def run_csharp_module(self) -> Dict[str, str]:
        """Executes C# binary asynchronously"""
        exe_path = os.path.join(settings.BIN_DIR, "RegistryInspector.exe")
        logger.info(f"Running C#: {exe_path}")
        
        if not os.path.exists(exe_path):
            result = {"Status": "Error", "Risk": "Binary Missing - Please Compile"}
            self.report_data["UAC_Check"] = result
            return result

        try:
            process = await asyncio.create_subprocess_exec(
                exe_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            status = stdout.decode().strip()
            risk = "HIGH" if "VULNERABLE" in status else "LOW"
            if "ERROR" in status:
                risk = "UNKNOWN"
                
            result = {"Status": status, "Risk": risk}
            self.report_data["UAC_Check"] = result
            
            if risk == "HIGH":
                self.fixes.append({
                    "desc": "Enable UAC (Secure Desktop)",
                    "cmd": 'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1'
                })
            
            return result
        except Exception as e:
            result = {"Status": "Error", "Risk": str(e)}
            self.report_data["UAC_Check"] = result
            return result

    def generate_remediation_script(self) -> str:
        """Generates remediation script"""
        if not self.fixes:
            return ""
        
        filename = os.path.join(settings.ROOT_DIR, f"REMEDIATION_{self.target_ip.replace('.','_')}.ps1")
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"# WINSEC DEFENDER REMEDIATION SCRIPT - {self.timestamp}\n")
                f.write("# RUN AS ADMINISTRATOR\n")
                f.write("$ErrorActionPreference = 'Stop'\n\n")
                
                for i, fix in enumerate(self.fixes, 1):
                    f.write(f"Write-Host 'Applying Fix {i}: {fix['desc']}' -ForegroundColor Cyan\n")
                    f.write(f"{fix['cmd']}\n")
                    f.write("if ($?) { Write-Host 'Success' -ForegroundColor Green } else { Write-Host 'Failed' -ForegroundColor Red }\n\n")
                
                f.write("Write-Host 'Remediation completed.' -ForegroundColor Green\n")
            return filename
        except Exception as e:
            logger.error(f"Failed to write remediation script: {e}")
            return ""
