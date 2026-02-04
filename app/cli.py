import argparse
import asyncio
import json
import logging
import sys
import os

# Ensure app is in path if run as script
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.context import ContextScanner
from app.core.strategies import (
    NetworkScanStrategy, ServiceConfigStrategy, 
    RegistryAuditStrategy, FileSystemStrategy
)

# Configure logging to stderr so it doesn't pollute JSON stdout
logging.basicConfig(level=logging.ERROR)

async def main():
    parser = argparse.ArgumentParser(description="WinSec Defender CLI")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP")
    parser.add_argument("--strategy", choices=["network", "service", "registry", "file", "all"], default="all")
    
    args = parser.parse_args()
    
    scanner = ContextScanner(args.target)
    
    strategies = {
        "network": NetworkScanStrategy(),
        "service": ServiceConfigStrategy(),
        "registry": RegistryAuditStrategy(),
        "file": FileSystemStrategy()
    }
    
    if args.strategy == "all":
        for s in strategies.values():
            scanner.add_strategy(s)
    else:
        scanner.add_strategy(strategies[args.strategy])
        
    results = await scanner.execute_scan()
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
             asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
