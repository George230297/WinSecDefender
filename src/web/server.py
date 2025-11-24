import sys
import os

# Ajuste de ruta para importar módulos hermanos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import uvicorn
from src.core.main_scanner import HybridScanner

app = FastAPI()

# Configurar templates
base_dir = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(base_dir, "templates"))

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/scan")
async def run_scan():
    try:
        scanner = HybridScanner("127.0.0.1")
        scanner.scan_network_ports()
        scanner.run_powershell_module()
        scanner.run_csharp_module()
        scanner.process_csharp_results()
        
        is_vulnerable = False
        if (scanner.report_data["System_Config"].get("SMBv1_Status") == "Enabled" or
            scanner.report_data["System_Config"].get("Unquoted_Services") != "None" or
            scanner.report_data["UAC_Check"].get("Risk") == "ALTO"):
            is_vulnerable = True

        return {
            "status": "success",
            "network": scanner.report_data.get("Network_Scan", []),
            "system": scanner.report_data.get("System_Config", {}),
            "uac": scanner.report_data.get("UAC_Check", {}),
            "vulnerable": is_vulnerable
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/sanitize")
async def run_sanitize():
    try:
        scanner = HybridScanner("127.0.0.1")
        scanner.scan_network_ports() # Necesario para poblar datos
        scanner.run_powershell_module()
        scanner.run_csharp_module()
        scanner.process_csharp_results()
        
        file_path = scanner.generate_remediation_script()
        return {"status": "success", "message": f"Script generado en: {file_path}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)