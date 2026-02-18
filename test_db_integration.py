
import requests
import json
import sys

BASE_URL = "http://127.0.0.1:8000/api"

def test_db_integration():
    print("--- Testing Database Integration ---")
    
    # 1. Analyze Rules
    rules = """
*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 80 -j ACCEPT
COMMIT
    """
    
    print("\n1. Sending Analysis Request...")
    try:
        response = requests.post(f"{BASE_URL}/analyze/", json={"rules": rules})
        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            sys.exit(1)
        
        data = response.json()
        session_id = data.get("session_id")
        if not session_id:
            print("Error: No session_id returned in response")
            sys.exit(1)
            
        print(f"Success! Session ID: {session_id}")
        
    except Exception as e:
        print(f"Failed to connect to API: {e}")
        sys.exit(1)

    # 2. Check History
    print("\n2. Checking History Endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/history/")
        if response.status_code != 200:
             print(f"Error: {response.status_code} - {response.text}")
             sys.exit(1)
             
        history = response.json()
        print(f"History contains {len(history)} entries.")
        
        # Check if our session is there
        found = False
        for entry in history:
            if entry["id"] == session_id:
                found = True
                print(f"Found session {session_id} in history:")
                print(json.dumps(entry, indent=2))
                break
        
        if not found:
            print(f"Error: Session {session_id} not found in history!")
            sys.exit(1)
            
        print("\n--- Verification Successful ---")

    except Exception as e:
        print(f"Failed to connect to API: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_db_integration()
