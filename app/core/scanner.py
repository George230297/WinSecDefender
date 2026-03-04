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
        from .mitre_mapper import MitreMapper
        
        self.context = ContextScanner(target_ip)
        self.mitre_mapper = MitreMapper()

    async def scan_network_ports(self) -> List[Dict[str, Any]]:
        """Async port scanning using Strategy"""
        from .strategies import NetworkScanStrategy
        self.context.set_strategy(NetworkScanStrategy())
        results = await self.context.execute_scan()
        
        # Extract specific result
        scan_result = results.get("Network_Scan", [])
        
        # We can enrich the wrapper dict to attach MITRE details to "Network_Scan"
        enriched_results = self.mitre_mapper.enrich_report(results)
        scan_result_enriched = enriched_results.get("Network_Scan", scan_result)
        
        self.report_data["Network_Scan"] = scan_result_enriched
        # Also preserve techniques if they were added at root
        if "mitre_techniques" in enriched_results:
            if "mitre_techniques" not in self.report_data:
                self.report_data["mitre_techniques"] = []
            self.report_data["mitre_techniques"].extend(enriched_results["mitre_techniques"])

        return scan_result_enriched

    async def run_powershell_module(self) -> Dict[str, Any]:
        """Executes PS1 script using Strategy"""
        from .strategies import ServiceConfigStrategy
        self.context.set_strategy(ServiceConfigStrategy())
        results = await self.context.execute_scan()
        
        ps_data = results.get("System_Config", {})
        if "error" in ps_data:
             return ps_data
             
        ps_data = self.mitre_mapper.enrich_report(ps_data)
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

        if ps_data.get("Unquoted_Services", "None") != "None" and ps_data.get("Unquoted_Services") != []:
            # Improved robust fix script with WQL optimization
            fix_code = r'''
# Optimized query to find candidates only (Server-Side Filtering)
$wql = "Select Name, PathName, StartMode From Win32_Service Where StartMode='Auto' AND PathName LIKE '% %'"
$candidates = Get-WmiObject -Query $wql -ErrorAction SilentlyContinue

foreach ($service in $candidates) {
    # Double check client-side safely
    if ($service.PathName -notmatch '^"' -and $service.PathName -match '\s' -and $service.PathName -notmatch '^C:\\Windows\\') {
        $newPath = '"' + $service.PathName + '"'
        Write-Output "Fixing $($service.Name)..."
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)" -Name "ImagePath" -Value $newPath -ErrorAction Stop
        } catch {
            Write-Error "Could not fix $($service.Name): $_"
        }
    }
}'''
            self.fixes.append({"desc": "Fix Unquoted Service Paths (Optimized)", "cmd": fix_code})

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
        uac_result = self.mitre_mapper.enrich_report(uac_result)
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
        fs_result = self.mitre_mapper.enrich_report(fs_result)
        self.report_data["FileSystem_Check"] = fs_result
        return fs_result

    def generate_remediation_content(self) -> str:
        """Generates remediation script content using template"""
        if not self.fixes:
            return ""
        
        template_path = os.path.join(settings.SCRIPTS_DIR, "remediation_template.ps1")
        if not os.path.exists(template_path):
            logger.error(f"Template not found: {template_path}")
            # Fallback to simple string if template missing
            return self._generate_fallback_remediation()

        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
        except Exception as e:
            logger.error(f"Error reading template: {e}")
            return self._generate_fallback_remediation()
        
        fix_blocks = []
        for i, fix in enumerate(self.fixes, 1):
            block = f"""
Write-Status "Applying Fix {i}: {fix['desc']}"
try {{
    {fix['cmd']}
    Write-Status "Success: {fix['desc']}" "Green"
}} catch {{
    Write-Error "Failed to apply fix: $_"
}}
"""
            fix_blocks.append(block)
        
        content = template.replace("{{ timestamp }}", self.timestamp)
        content = content.replace("{{ fix_blocks }}", "\n".join(fix_blocks))
        
        return content

    def _generate_fallback_remediation(self) -> str:
        """Fallback generation if template is missing"""
        content = []
        content.append(f"# WINSEC DEFENDER REMEDIATION SCRIPT - {self.timestamp}")
        content.append("# RUN AS ADMINISTRATOR")
        for fix in self.fixes:
            content.append(f"Write-Host 'Applying: {fix['desc']}'")
            content.append(fix['cmd'])
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
