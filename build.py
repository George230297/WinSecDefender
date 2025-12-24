import os
import subprocess
import sys

def compile_csharp():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    scripts_dir = os.path.join(base_dir, "scripts")
    bin_dir = os.path.join(base_dir, "bin")
    
    source_file = os.path.join(scripts_dir, "RegistryInspector.cs")
    output_file = os.path.join(bin_dir, "RegistryInspector.exe")
    
    if not os.path.exists(bin_dir):
        os.makedirs(bin_dir)
        
    if not os.path.exists(source_file):
        print(f"Error: Source file not found: {source_file}")
        return False

    # Check for csc.exe (C# Compiler)
    csc_path = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    if not os.path.exists(csc_path):
        # Try finding newer version or generic
        print("Warning: default csc.exe not found. Trying 'csc' in PATH.")
        csc_path = "csc"

    print(f"Compiling {source_file} -> {output_file}...")
    try:
        cmd = [csc_path, f"/out:{output_file}", source_file]
        subprocess.run(cmd, check=True)
        print("Compilation successful.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Compilation failed: {e}")
        return False
    except FileNotFoundError:
        print("Error: csc compiler not found in PATH or standard location.")
        print("Please install .NET Framework or add csc to PATH.")
        return False

if __name__ == "__main__":
    compile_csharp()
