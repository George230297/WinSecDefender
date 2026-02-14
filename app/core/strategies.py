import asyncio
import os
import json
import logging
from typing import Dict, Any, List
from .interfaces import IScanStrategy
from .config import settings

logger = logging.getLogger(__name__)

class NetworkScanStrategy(IScanStrategy):
    async def scan(self, target: str) -> Dict[str, Any]:
        logger.info(f"Scanning ports on {target}...")
        common_ports = {
            21: "FTP (File Transfer)",
            445: "SMB (Windows File Sharing)",
            3389: "RDP (Remote Desktop)"
        }
        
        async def check_port(port, desc):
            try:
                 future = asyncio.open_connection(target, port)
                 reader, writer = await asyncio.wait_for(future, timeout=0.5)
                 writer.close()
                 await writer.wait_closed()
                 return {"port": port, "service": desc, "status": "OPEN"}
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

        tasks = [check_port(port, desc) for port, desc in common_ports.items()]
        results = await asyncio.gather(*tasks)
        
        open_ports = [r for r in results if r is not None]
        return {"Network_Scan": open_ports}

class ServiceConfigStrategy(IScanStrategy):
    async def scan(self, target: str) -> Dict[str, Any]:
        ps_script_path = os.path.join(settings.SCRIPTS_DIR, "audit_script.ps1")
        logger.info(f"Running PowerShell: {ps_script_path}")
        
        if not os.path.exists(ps_script_path):
            logger.error(f"Script not found: {ps_script_path}")
            return {"error": "Script not found"}

        try:
            process = await asyncio.create_subprocess_exec(
                "powershell", "-ExecutionPolicy", "Bypass", "-File", ps_script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if stdout:
                try:
                    # Attempt to decode using system encoding, fallback to utf-8 with replacement
                    try:
                        decoded_out = stdout.decode("utf-8").strip()
                    except UnicodeDecodeError:
                        # Fallback for Windows CP1252/CP850
                        decoded_out = stdout.decode("mbcs", errors="replace").strip()
                        
                    ps_data = json.loads(decoded_out)
                    return {"System_Config": ps_data}
                except json.JSONDecodeError:
                    logger.error("Failed to decode PowerShell JSON output")
                    return {"error": "Invalid JSON output", "raw": stdout.decode("mbcs", errors="replace")}
            else:
                 logger.error(f"PowerShell Error: {stderr.decode()}")
                 return {"error": stderr.decode()}

        except Exception as e:
            logger.error(f"PowerShell execution failed: {str(e)}")
            return {"error": str(e)}

class RegistryAuditStrategy(IScanStrategy):
    async def scan(self, target: str) -> Dict[str, Any]:
        # Note: target IP is ignored here as this runs locally, but interface requires it
        exe_path = os.path.join(settings.BIN_DIR, "RegistryInspector.exe")
        logger.info(f"Running C# Registry Inspector: {exe_path}")
        
        if not os.path.exists(exe_path):
             return {"UAC_Check": {"Status": "Error", "Risk": "Binary Missing - Please Compile"}}

        try:
            # Default check for UAC
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            value_name = "EnableLUA"
            expected_val = "1"

            process = await asyncio.create_subprocess_exec(
                exe_path, key_path, value_name, expected_val,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            output_str = stdout.decode().strip()
            # Try to find JSON in output (lines might contain noise)
            status_output = "UNKNOWN"
            risk = "UNKNOWN"
            
            try:
                # Find the last line that looks like JSON
                import json
                last_line = output_str.splitlines()[-1] if output_str else ""
                data = json.loads(last_line)
                
                status_output = data.get("status", "UNKNOWN")
                if status_output == "SECURE":
                    risk = "LOW"
                elif status_output == "VULNERABLE":
                    risk = "HIGH"
                else:
                    risk = "UNKNOWN" # ERROR case
                    
            except (json.JSONDecodeError, IndexError):
                # Fallback to legacy text parsing or just report raw
                logger.warning(f"Failed to parse C# JSON: {output_str}")
                if "VULNERABLE" in output_str:
                    status_output = "VULNERABLE"
                    risk = "HIGH"
                elif "SECURE" in output_str:
                    status_output = "SECURE"
                    risk = "LOW"
                else: 
                    status_output = f"Raw: {output_str}"

            result = {"Status": status_output, "Risk": risk, "Check": f"{key_path}\\{value_name}"}
            return {"UAC_Check": result}
        except Exception as e:
            return {"UAC_Check": {"Status": "Error", "Risk": str(e)}}

class FileSystemStrategy(IScanStrategy):
    async def scan(self, target: str) -> Dict[str, Any]:
        logger.info("Checking critical file permissions...")
        # Simple check: Is hosts file writable?
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        results = {}
        
        if os.path.exists(hosts_path):
            if os.access(hosts_path, os.W_OK):
                results["Hosts_File"] = {"Status": "Writable", "Risk": "HIGH", "Path": hosts_path}
            else:
                results["Hosts_File"] = {"Status": "Secure", "Risk": "LOW", "Path": hosts_path}
        else:
             results["Hosts_File"] = {"Status": "Missing", "Risk": "UNKNOWN", "Path": hosts_path}
             
        return {"FileSystem_Check": results}
