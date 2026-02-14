from pydantic_settings import BaseSettings
from pydantic import Field
import os
import secrets
import string

class Settings(BaseSettings):
    PROJECT_NAME: str = "WinSecDefender"
    VERSION: str = "2.1.0"
    
    # Paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ROOT_DIR: str = os.path.dirname(BASE_DIR)
    SCRIPTS_DIR: str = os.path.join(ROOT_DIR, "scripts")
    BIN_DIR: str = os.path.join(ROOT_DIR, "bin")
    
    # Logging
    LOG_FILE: str = os.path.join(ROOT_DIR, "audit.log")
    
    # Security
    # Default to "admin" if not set in .env
    AUTH_USERNAME: str = Field(default="admin", env="WINSEC_ADMIN_USER")
    # Default to None so we can detect if it's missing/default
    AUTH_PASSWORD: str = Field(default="", env="WINSEC_ADMIN_PASSWORD")
    
    # SSL/TLS (Optional)
    SSL_KEYFILE: str = ""
    SSL_CERTFILE: str = ""
    
    # Scanner Settings
    TARGET_IP: str = "127.0.0.1"
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()

# Security Check: Generate random password if not set or default
if not settings.AUTH_PASSWORD or settings.AUTH_PASSWORD == "admin123":
    # Generate a strong random password
    chars = string.ascii_letters + string.digits + "!@#$%"
    generated_pwd = ''.join(secrets.choice(chars) for _ in range(16))
    settings.AUTH_PASSWORD = generated_pwd
    
    print("\n" + "="*60)
    print("WARNING: No secure password found in .env (WINSEC_ADMIN_PASSWORD).")
    print(f"Generated Temporary Admin Password: {generated_pwd}")
    print("PLEASE SAVE THIS PASSWORD OR CONFIGURE .env IMMEDIATELEY.")
    print("="*60 + "\n")
