import socket
import subprocess
import json
import os
import sys
from datetime import datetime

class HybridScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.report_data = {}
        self.fixes = [] 
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Rutas dinámicas base
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.root_dir = os.path.abspath(os.path.join(self.base_dir, "../../"))
        self.bin_dir = os.path.join(self.root_dir, "bin")

    def scan_network_ports(self):
        """Escaneo de sockets"""
        print(f"[*] Escaneando puertos en {self.target_ip}...")
        common_ports = {
            21: "FTP (Transferencia Archivos)",
            445: "SMB (Archivos Windows)",
            3389: "RDP (Escritorio Remoto)"
        }
        open_ports = []
        for port, desc in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    open_ports.append({"port": port, "service": desc, "status": "OPEN"})
                sock.close()
            except: pass
        
        self.report_data["Network_Scan"] = open_ports

    def run_powershell_module(self):
        """Ejecuta PS1 desde la carpeta src/core"""
        ps_script_path = os.path.join(self.base_dir, "audit_script.ps1")
        print(f"[*] Ejecutando PowerShell: {ps_script_path}")
        
        try:
            cmd = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", ps_script_path],
                capture_output=True, text=True
            )
            if cmd.stdout.strip():
                ps_data = json.loads(cmd.stdout)
                self.report_data["System_Config"] = ps_data
                
                # Generar Fixes
                if ps_data.get("SMBv1_Status") == "Enabled":
                    self.fixes.append({
                        "desc": "Deshabilitar SMBv1 (WannaCry Risk)",
                        "cmd": "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
                    })

                if ps_data.get("Unquoted_Services") != "None":
                    fix_code = r'''
$services = Get-WmiObject win32_service | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -notmatch '^"' -and $_.PathName -match '\s' }
foreach ($service in $services) {
    $newPath = '"' + $service.PathName + '"'
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)" -Name "ImagePath" -Value $newPath
}'''
                    self.fixes.append({"desc": "Corregir Unquoted Service Paths", "cmd": fix_code})
        except Exception as e:
            print(f"[!] Error PS: {e}")

    def run_csharp_module(self):
        """Ejecuta el binario C# desde la carpeta bin"""
        exe_path = os.path.join(self.bin_dir, "RegistryInspector.exe")
        print(f"[*] Ejecutando C#: {exe_path}")
        
        if not os.path.exists(exe_path):
            self.report_data["UAC_Check"] = {"Status": "Error", "Risk": "Binary Missing"}
            return

        try:
            cmd = subprocess.run([exe_path], capture_output=True, text=True)
            status = cmd.stdout.strip()
            risk = "ALTO" if "VULNERABLE" in status else "BAJO"
            self.report_data["UAC_Check"] = {"Status": status, "Risk": risk}
        except Exception as e:
            self.report_data["UAC_Check"] = {"Status": "Error", "Risk": str(e)}

    def process_csharp_results(self):
        uac = self.report_data.get("UAC_Check", {})
        if uac.get("Risk") == "ALTO":
            self.fixes.append({
                "desc": "Habilitar UAC (Secure Desktop)",
                "cmd": 'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1'
            })

    def generate_remediation_script(self):
        """Genera el script en la RAÍZ del proyecto"""
        if not self.fixes: return
        
        filename = os.path.join(self.root_dir, f"SANITIZAR_{self.target_ip.replace('.','_')}.ps1")
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"# SCRIPT DE SANITIZACIÓN - {self.timestamp}\n")
            f.write("$ErrorActionPreference = 'Stop'\n\n")
            for i, fix in enumerate(self.fixes, 1):
                f.write(f"Write-Host 'Aplicando Fix {i}: {fix['desc']}'\n")
                f.write(f"{fix['cmd']}\n\n")
            f.write("Write-Host 'Sanitización completada.' -ForegroundColor Green\n")
        
        return filename