import requests
import json
import sys

# Your Google API key (same key can be used if Web Risk is enabled for your project)
API_KEY = "AIzaSyB6vzz-SpCUVzB5nXdx9Mjag6Wg6cCH3Ok"
ENDPOINT = f"https://webrisk.googleapis.com/v1/uris:search?key={API_KEY}"

def check_url(url_to_check):
    params = {
        "uri": url_to_check,
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]
    }

    try:
        resp = requests.get(ENDPOINT, params=params, timeout=10)
    except requests.RequestException as e:
        print("Network/API error:", e)
        return

    print(f"\nHTTP {resp.status_code}")
    try:
        j = resp.json()
    except ValueError:
        print("Non-JSON response:", resp.text)
        return

    # Show raw JSON (for debugging)
    print("Raw response JSON:", json.dumps(j, indent=2))

    if "threat" in j:
        print(f"⚠️  The URL '{url_to_check}' is flagged as dangerous!")
        threat = j["threat"]
        print(f" - Threat Type(s): {threat.get('threatTypes')}")
        print(f" - Expire Time: {threat.get('expireTime')}")
    else:
        print(f"✅ The URL '{url_to_check}' appears safe (no threats found).")

if __name__ == "__main__":
    tests = [
        "https://www.google.com",  # benign
        "https://testsafebrowsing.appspot.com/s/phishing.html"  # guaranteed phishing test page
    ]
    for t in tests:
        print("\nChecking:", t)
        check_url(t)

    while True:
        u = input("\nEnter URL to check (or 'exit'): ").strip()
        if u.lower() == "exit" or u == "":
            sys.exit(0)
        check_url(u)
