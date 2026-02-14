from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.api.routes import router
from app.core.config import settings
import uvicorn
import os
import sys
import logging

# Configure Audit Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(settings.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("audit")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Windows Security Hardening & Vulnerability Scanner"
)

# Mount Static if it exists (create if not)
static_dir = os.path.join(settings.BASE_DIR, "app/static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir)

app.mount("/static", StaticFiles(directory=static_dir), name="static")

app.include_router(router)

@app.on_event("startup")
async def startup_check():
    bin_path = os.path.join(settings.BIN_DIR, "RegistryInspector.exe")
    if not os.path.exists(bin_path):
        logger.warning("RegistryInspector.exe not found. Attempting to build...")
        try:
            # Append root dir to sys.path to ensure build.py can be imported if needed
            if settings.ROOT_DIR not in sys.path:
                sys.path.append(settings.ROOT_DIR)
            import build
            if build.compile_csharp():
                logger.info("RegistryInspector.exe built successfully.")
            else:
                logger.error("Failed to build RegistryInspector.exe. C# Strategy will be unavailable.")
        except ImportError:
            logger.error("Could not import build.py. Please run 'python build.py' manually.")
        except Exception as e:
            logger.error(f"Error during startup build: {e}")

if __name__ == "__main__":
    print(f"Starting {settings.PROJECT_NAME} v{settings.VERSION}")
    print(f"Dashboard available at http://127.0.0.1:8000")
    print(f"Audit log: {settings.LOG_FILE}")
    
    # SSL Context
    ssl_config = {}
    if settings.SSL_KEYFILE and settings.SSL_CERTFILE:
        if os.path.exists(settings.SSL_KEYFILE) and os.path.exists(settings.SSL_CERTFILE):
            print("Running in HTTPS mode (Secure)")
            ssl_config["ssl_keyfile"] = settings.SSL_KEYFILE
            ssl_config["ssl_certfile"] = settings.SSL_CERTFILE
        else:
            print("Warning: SSL files configured but not found. Fallback to HTTP.")
    
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True, **ssl_config)
