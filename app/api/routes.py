from fastapi import APIRouter, Request, BackgroundTasks, Response, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from app.core.config import settings
from app.core.scanner import HybridScanner
import uuid
import logging
from typing import Dict, Any

# Audit Logger
logger = logging.getLogger("audit")

router = APIRouter()
templates = Jinja2Templates(directory=settings.BASE_DIR + "/app/templates")
security = HTTPBasic()

# In-memory job store (Use Redis for production)
jobs: Dict[str, Any] = {}

def check_auth(credentials: HTTPBasicCredentials = Depends(security)):
    is_correct_username = credentials.username == settings.AUTH_USERNAME
    is_correct_password = credentials.password == settings.AUTH_PASSWORD
    if not (is_correct_username and is_correct_password):
        logger.warning(f"Failed login attempt from user: {credentials.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@router.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    # Public Dashboard (Read-only view could be public, but actions need auth)
    # For now, we leave the dashboard public but the buttons will fail if API is secured.
    # Ideally, frontend should handle auth challenge.
    return templates.TemplateResponse("index.html", {"request": request})

async def perform_scan(job_id: str, username: str):
    logger.info(f"Scan Job {job_id} started by {username}")
    try:
        scanner = HybridScanner()
        await scanner.scan_network_ports()
        await scanner.run_powershell_module()

        await scanner.run_csharp_module()
        await scanner.run_filesystem_module()
        
        uac = scanner.report_data.get("UAC_Check", {})
        sys_config = scanner.report_data.get("System_Config", {})
        fs_check = scanner.report_data.get("FileSystem_Check", {})
        
        is_vulnerable = False
        if (sys_config.get("SMBv1_Status") == "Enabled" or
            sys_config.get("Unquoted_Services") != "None" or
            uac.get("Risk") == "HIGH" or
            any(f.get("Risk") == "HIGH" for f in fs_check.values())):
            is_vulnerable = True
            
        result = {
            "status": "success",
            "network": scanner.report_data.get("Network_Scan", []),
            "system": sys_config,
            "uac": uac,
            "filesystem": fs_check,
            "vulnerable": is_vulnerable
        }
        
        jobs[job_id] = {"status": "completed", "result": result}
        logger.info(f"Scan Job {job_id} completed successfully")
    except Exception as e:
        logger.error(f"Scan Job {job_id} failed: {e}")
        jobs[job_id] = {"status": "failed", "error": str(e)}

@router.get("/api/scan")
async def run_scan_background(background_tasks: BackgroundTasks, username: str = Depends(check_auth)):
    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "processing"}
    background_tasks.add_task(perform_scan, job_id, username)
    logger.info(f"Scan requested by {username}. Job ID: {job_id}")
    return {"job_id": job_id, "status": "started"}

@router.get("/api/status/{job_id}")
async def get_scan_status(job_id: str, username: str = Depends(check_auth)):
    job = jobs.get(job_id)
    if not job:
        return JSONResponse(status_code=404, content={"error": "Job not found"})
    return job

@router.post("/api/sanitize")
async def run_sanitize(username: str = Depends(check_auth)):
    logger.info(f"Remediation script requested by {username}")
    scanner = HybridScanner()
    
    # We run checks again to ensure fresh fix generation
    # Ideally optimize to use cached results from scan job
    await scanner.scan_network_ports()
    await scanner.run_powershell_module()

    await scanner.run_csharp_module()
    await scanner.run_filesystem_module()
    
    content = scanner.generate_remediation_content()
    
    if content:
        logger.info(f"Remediation script generated for {username}")
        return Response(
            content=content,
            media_type="application/octet-stream",
            headers={"Content-Disposition": "attachment; filename=REMEDIATION_SCRIPT.ps1"}
        )
    else:
        logger.info(f"No fixes needed for {username}")
        return JSONResponse(status_code=400, content={"status": "error", "message": "No fixes needed"})
