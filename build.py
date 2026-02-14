import os
import subprocess
import sys
import logging

# Configure logging for build script
logging.basicConfig(level=logging.INFO, format="[BUILD] %(message)s")
logger = logging.getLogger("build")

def compile_csharp():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    scripts_dir = os.path.join(base_dir, "scripts")
    bin_dir = os.path.join(base_dir, "bin")
    
    source_file = os.path.join(scripts_dir, "RegistryInspector.cs")
    output_file = os.path.join(bin_dir, "RegistryInspector.exe")
    
    if not os.path.exists(bin_dir):
        os.makedirs(bin_dir)
        
    if not os.path.exists(source_file):
        logger.error(f"Source file not found: {source_file}")
        return False

    # Check for csc.exe (C# Compiler)
    csc_path = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    if not os.path.exists(csc_path):
        # Try finding newer version or generic
        logger.warning("Default csc.exe not found. Trying 'csc' in PATH.")
        csc_path = "csc"

    logger.info(f"Compiling {source_file} -> {output_file}...")
    try:
        cmd = [csc_path, f"/out:{output_file}", source_file]
        # Capture output to avoid cluttering stdout unless error
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logger.info("Compilation successful.")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Compilation failed: {e}")
        logger.error(f"Compiler Output: {e.stdout}")
        logger.error(f"Compiler Errors: {e.stderr}")
        return False
    except FileNotFoundError:
        logger.error("csc compiler not found in PATH or standard location.")
        logger.error("Please install .NET Framework or add csc to PATH.")
        return False

if __name__ == "__main__":
    if not compile_csharp():
        sys.exit(1)
