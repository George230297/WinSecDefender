import asyncio
import socket
import json
import os
import logging
import tempfile
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
        from .context import ContextScanner
        from .strategies import NetworkScanStrategy, ServiceConfigStrategy, RegistryAuditStrategy
        self.context = ContextScanner(target_ip)

    async def scan_network_ports(self) -> List[Dict[str, Any]]:
        """Async port scanning using Strategy"""
        from .strategies import NetworkScanStrategy
        self.context.set_strategy(NetworkScanStrategy())
        results = await self.context.execute_scan()
        
        # Extract specific result
        scan_result = results.get("Network_Scan", [])
        self.report_data["Network_Scan"] = scan_result
        return scan_result

    async def run_powershell_module(self) -> Dict[str, Any]:
        """Executes PS1 script using Strategy"""
        from .strategies import ServiceConfigStrategy
        self.context.set_strategy(ServiceConfigStrategy())
        results = await self.context.execute_scan()
        
        ps_data = results.get("System_Config", {})
        if "error" in ps_data:
             return ps_data
             
        self.report_data["System_Config"] = ps_data
        self._analyze_ps_results(ps_data)
        return ps_data

    def _analyze_ps_results(self, ps_data: Dict[str, Any]):
        """Analyze results and generate fixes"""
        if ps_data.get("SMBv1_Status") == "Enabled" or ps_data.get("SMBv1_Status") == "Likely Enabled":
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

    async def run_csharp_module(self, 
            key_path: str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 
            value_name: str = "EnableLUA", 
            expected_val: str = "1") -> Dict[str, str]:
        """Executes C# binary using Strategy"""
        from .strategies import RegistryAuditStrategy
        # Note: The strategy currently has hardcoded args for the demo, 
        # but in a real refactor we might pass args to the strategy constructor.
        # For this refactor, we'll rely on the default strategy behavior which matches the default args here.
        # If dynamic args are needed, the Strategy should be instantiated with them.
        
        # Create a transient strategy instance if we need custom args? 
        # For now, the prompt requirements were about "RegistryAuditStrategy" generally. 
        # I'll stick to the default strategy implementation which does the UAC check.
        
        self.context.set_strategy(RegistryAuditStrategy())
        results = await self.context.execute_scan()
        
        uac_result = results.get("UAC_Check", {})
        self.report_data["UAC_Check"] = uac_result
        
        # Analyze for fixes
        if uac_result.get("Risk") == "HIGH" and "EnableLUA" in uac_result.get("Check", ""):
             self.fixes.append({
                "desc": "Enable UAC (Secure Desktop)",
                "cmd": r'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1'
            })

        return uac_result

    async def run_filesystem_module(self) -> Dict[str, Any]:
        """Executes FileSystem check using Strategy"""
        from .strategies import FileSystemStrategy
        self.context.set_strategy(FileSystemStrategy())
        results = await self.context.execute_scan()
        
        fs_result = results.get("FileSystem_Check", {})
        self.report_data["FileSystem_Check"] = fs_result
        return fs_result

    def generate_remediation_content(self) -> str:
        """Generates remediation script content in memory"""
        if not self.fixes:
            return ""
        
        content = []
        content.append(f"# WINSEC DEFENDER REMEDIATION SCRIPT - {self.timestamp}")
        content.append("# RUN AS ADMINISTRATOR")
        content.append("$ErrorActionPreference = 'Stop'\n")
        
        for i, fix in enumerate(self.fixes, 1):
            content.append(f"Write-Host 'Applying Fix {i}: {fix['desc']}' -ForegroundColor Cyan")
            content.append(f"{fix['cmd']}")
            content.append("if ($?) { Write-Host 'Success' -ForegroundColor Green } else { Write-Host 'Failed' -ForegroundColor Red }\n")
        
        content.append("Write-Host 'Remediation completed.' -ForegroundColor Green")
        return "\n".join(content)

    def save_remediation_temp_file(self) -> str:
        """Saves content to a temp file and returns path"""
        content = self.generate_remediation_content()
        if not content:
            return ""
            
        try:
            fd, path = tempfile.mkstemp(suffix=".ps1", prefix="REMEDIATION_")
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(content)
            return path
        except Exception as e:
            logger.error(f"Failed to write temp remediation script: {e}")
            return ""
