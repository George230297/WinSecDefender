import unittest
import os
import sys
import shutil

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import settings
from app.core.scanner import HybridScanner
import build

class TestWinSecDefender(unittest.TestCase):
    
    def test_01_config_security(self):
        """Verify that security config generates a password if missing"""
        print(f"\n[TEST] Admin User: {settings.AUTH_USERNAME}")
        # We expect a generated password or one from env
        self.assertTrue(settings.AUTH_PASSWORD, "Password should be set")
        self.assertNotEqual(settings.AUTH_PASSWORD, "admin123", "Should not be default if we are simulating prod")

    def test_02_build_system(self):
        """Verify build script availability and function"""
        # Ensure bin dir exists
        if not os.path.exists(settings.BIN_DIR):
            os.makedirs(settings.BIN_DIR)
            
        # Clean previous build to test compilation
        exe_path = os.path.join(settings.BIN_DIR, "RegistryInspector.exe")
        if os.path.exists(exe_path):
            os.remove(exe_path)
            
        print("[TEST] Compiling C# component...")
        success = build.compile_csharp()
        self.assertTrue(success, "Build should succeed")
        self.assertTrue(os.path.exists(exe_path), "EXE should exist after build")

    def test_03_remediation_generation(self):
        """Verify remediation script generation from template"""
        scanner = HybridScanner()
        # Add a dummy fix
        scanner.fixes.append({"desc": "Test Fix", "cmd": "Write-Host 'Fixed'"})
        
        content = scanner.generate_remediation_content()
        # Template uses "WinSec Defender Remediation Script" in Synopsis
        self.assertTrue("WinSec Defender Remediation Script" in content or "WINSEC DEFENDER REMEDIATION SCRIPT" in content, "Header not found")
        self.assertIn("Test Fix", content)
        self.assertIn("Write-Host 'Fixed'", content)
        print("[TEST] Remediation content generated successfully.")

if __name__ == '__main__':
    unittest.main()
