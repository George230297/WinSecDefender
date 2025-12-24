from fastapi import APIRouter, Request, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.core.config import settings
from app.core.scanner import HybridScanner
from app.models.schemas import ScanResponse, RemediationResponse
import os

router = APIRouter()
templates = Jinja2Templates(directory=settings.BASE_DIR + "/app/templates")

@router.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@router.get("/api/scan", response_model=ScanResponse)
async def run_scan():
    scanner = HybridScanner()
    
    # Run scans concurrently
    await scanner.scan_network_ports()
    await scanner.run_powershell_module()
    await scanner.run_csharp_module()
    
    # Create Response
    uac = scanner.report_data.get("UAC_Check", {})
    sys_config = scanner.report_data.get("System_Config", {})
    
    is_vulnerable = False
    if (sys_config.get("SMBv1_Status") == "Enabled" or
        sys_config.get("Unquoted_Services") != "None" or
        uac.get("Risk") == "HIGH"):
        is_vulnerable = True
        
    return {
        "status": "success",
        "network": scanner.report_data.get("Network_Scan", []),
        "system": sys_config,
        "uac": uac,
        "vulnerable": is_vulnerable
    }

@router.post("/api/sanitize", response_model=RemediationResponse)
async def run_sanitize():
    scanner = HybridScanner()
    
    # We need to run checks to generate the fix list
    await scanner.scan_network_ports()
    await scanner.run_powershell_module()
    await scanner.run_csharp_module()
    
    file_path = scanner.generate_remediation_script()
    
    if file_path:
        return {"status": "success", "message": "Remediation script generated successfully", "file_path": file_path}
    else:
        return {"status": "error", "message": "No fixes needed or error generating script"}
