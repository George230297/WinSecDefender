from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class PortResult(BaseModel):
    port: int
    service: str
    status: str

class UACResult(BaseModel):
    Status: str
    Risk: str

class ScanResponse(BaseModel):
    status: str
    network: List[PortResult] = []
    system: Dict[str, Any] = {}
    uac: UACResult = {}
    vulnerable: bool

class RemediationResponse(BaseModel):
    status: str
    message: str
    file_path: Optional[str] = None
