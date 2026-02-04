import asyncio
import sys
import os
import logging
import json

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.api.routes import perform_scan, jobs

# Configure logging
logging.basicConfig(level=logging.ERROR)

async def test_api_scan():
    print("Starting API Scan Verification...")
    job_id = "test_job_1"
    username = "test_user"
    
    # Run the scan logic directly
    await perform_scan(job_id, username)
    
    # Check results
    result = jobs.get(job_id)
    if not result:
        print("FAIL: Job not found in jobs dict")
        sys.exit(1)
        
    status = result.get("status")
    data = result.get("result", {})
    
    print(f"Job Status: {status}")
    
    if status != "completed":
        print(f"FAIL: Job failed with error: {result.get('error')}")
        sys.exit(1)
        
    # Verify all sections are present
    sections = ["network", "system", "uac", "filesystem"]
    for sec in sections:
        if sec in data:
            print(f"PASS: Section '{sec}' found.")
            # Print a snippet of the data
            print(f"  -> {str(data[sec])[:100]}...") 
        else:
            print(f"FAIL: Section '{sec}' MISSING in report.")
            sys.exit(1)

    print("\nAPI Logic Verification SUCCESS!")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(test_api_scan())
