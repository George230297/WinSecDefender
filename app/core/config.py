from pydantic_settings import BaseSettings
import os

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
    
    # Security (Defaults to random if not set in .env)
    AUTH_USERNAME: str = "admin"
    AUTH_PASSWORD: str = "admin123" # Change in production!
    
    # SSL/TLS (Optional)
    SSL_KEYFILE: str = ""
    SSL_CERTFILE: str = ""
    
    # Scanner Settings
    TARGET_IP: str = "127.0.0.1"
    
    class Config:
        env_file = ".env"

settings = Settings()
